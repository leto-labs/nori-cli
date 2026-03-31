//! SACP v11-based ACP connection layer.
//!
//! This replaces the old `AcpConnection` which required a dedicated worker thread
//! due to the `!Send` futures in `agent-client-protocol` v0.9. SACP v11's
//! `ConnectionTo<Agent>` is `Send + Sync`, allowing direct async usage from the main
//! tokio runtime without a dedicated thread or `LocalSet`.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use agent_client_protocol_schema as acp;
use anyhow::Context;
use anyhow::Result;
use futures::AsyncBufReadExt;
use futures::io::BufReader;
use sacp::Agent;
use sacp::ByteStreams;
use sacp::Client;
use sacp::ConnectionTo;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::debug;
use tracing::warn;

use super::AcpModelState;
use super::ApprovalEventType;
use super::ApprovalRequest;
use super::ConnectionEvent;
use crate::registry::AcpAgentConfig;
use crate::translator;

#[cfg(feature = "unstable")]
use sacp::UntypedMessage;

/// Minimum supported ACP protocol version.
const MINIMUM_SUPPORTED_VERSION: acp::ProtocolVersion = acp::ProtocolVersion::V1;

struct TerminalState {
    child: StdMutex<std::process::Child>,
    output: StdMutex<String>,
    truncated: StdMutex<bool>,
    exit_status: StdMutex<Option<acp::TerminalExitStatus>>,
    output_byte_limit: Option<u64>,
}

impl TerminalState {
    fn new(child: std::process::Child, output_byte_limit: Option<u64>) -> Self {
        Self {
            child: StdMutex::new(child),
            output: StdMutex::new(String::new()),
            truncated: StdMutex::new(false),
            exit_status: StdMutex::new(None),
            output_byte_limit,
        }
    }
}

/// A thread-safe connection to an ACP agent subprocess using SACP v11.
///
/// Unlike the old `AcpConnection`, this does NOT require a dedicated worker thread.
/// SACP v11's `ConnectionTo<Agent>` is `Send + Sync`, allowing all operations to run
/// directly on the main tokio runtime.
///
/// Internal architecture:
/// - A background tokio task runs the SACP connection via `connect_with`.
/// - The `ConnectionTo<Agent>` is cloned out and used for all subsequent requests.
/// - Session notifications and approval requests are forwarded via channels.
/// - All session-domain traffic flows through a single ordered inbox.
pub struct SacpConnection {
    /// Connection context for sending requests to the agent.
    cx: ConnectionTo<Agent>,

    /// Agent capabilities from the initialization handshake.
    agent_capabilities: acp::AgentCapabilities,

    /// Ordered inbox of raw ACP events from the transport layer.
    event_rx: mpsc::Receiver<ConnectionEvent>,

    /// Thread-safe model state, updated on session creation and model switch.
    model_state: std::sync::Arc<std::sync::RwLock<AcpModelState>>,

    /// Thread-safe session config snapshot, updated on session creation/load,
    /// explicit config changes, and `ConfigOptionUpdate` notifications.
    session_config_options: std::sync::Arc<std::sync::RwLock<Vec<acp::SessionConfigOption>>>,

    /// Handle to the background task driving the SACP connection.
    connection_task: tokio::task::JoinHandle<()>,

    /// Handle to the child process for cleanup.
    child: std::sync::Arc<Mutex<Child>>,

    /// Handle to the stderr logging task.
    stderr_task: tokio::task::JoinHandle<()>,
}

impl SacpConnection {
    /// Spawn a new ACP agent subprocess and establish a SACP v11 connection.
    pub async fn spawn(config: &AcpAgentConfig, cwd: &Path) -> Result<Self> {
        debug!(
            "Spawning ACP agent (SACP v11): {} {:?} in {}",
            config.command,
            config.args,
            cwd.display()
        );

        // --- Spawn the agent subprocess ---
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .envs(&config.env)
            .env_remove("CODEX_HOME")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Process group isolation and parent death signal.
        #[cfg(unix)]
        unsafe {
            #[cfg(target_os = "linux")]
            let parent_pid = libc::getpid();

            cmd.pre_exec(move || {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                #[cfg(target_os = "linux")]
                {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        libc::raise(libc::SIGTERM);
                    }
                }

                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn ACP agent: {}", config.command))?;

        let stdout = child.stdout.take().context("Failed to take stdout")?;
        let stdin = child.stdin.take().context("Failed to take stdin")?;
        let stderr = child.stderr.take().context("Failed to take stderr")?;

        debug!("ACP agent spawned (pid: {:?})", child.id());

        // Log stderr in background.
        let stderr_task = tokio::spawn(async move {
            let mut stderr = BufReader::new(stderr.compat());
            let mut line = String::new();
            while let Ok(n) = stderr.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                warn!("ACP agent stderr: {}", line.trim());
                line.clear();
            }
        });

        // --- Set up channels ---
        let (event_tx, event_rx) = mpsc::channel::<ConnectionEvent>(1024);

        // --- Build SACP connection ---
        let transport = ByteStreams::new(stdin.compat_write(), stdout.compat());

        let event_tx_for_notifications = event_tx.clone();
        let event_tx_for_write = event_tx.clone();
        let event_tx_for_read = event_tx.clone();
        let approval_cwd = cwd.to_path_buf();
        let write_cwd = cwd.to_path_buf();
        let read_cwd = cwd.to_path_buf();
        let session_config_options =
            std::sync::Arc::new(std::sync::RwLock::new(Vec::<acp::SessionConfigOption>::new()));
        let session_config_options_for_notifications =
            std::sync::Arc::clone(&session_config_options);
        let terminals =
            Arc::new(StdMutex::new(HashMap::<acp::TerminalId, Arc<TerminalState>>::new()));
        let terminals_for_create = Arc::clone(&terminals);
        let terminals_for_kill = Arc::clone(&terminals);
        let terminals_for_release = Arc::clone(&terminals);
        let terminals_for_output = Arc::clone(&terminals);
        let terminals_for_wait = Arc::clone(&terminals);
        let terminal_cwd = cwd.to_path_buf();

        // Oneshot to receive the connection context and init result from inside connect_with.
        let (init_tx, init_rx) =
            oneshot::channel::<Result<(ConnectionTo<Agent>, acp::AgentCapabilities)>>();

        let child = std::sync::Arc::new(Mutex::new(child));

        let connection_task = tokio::spawn(async move {
            let result = Client
                .builder()
                .on_receive_notification(
                    {
                        let event_tx = event_tx_for_notifications;
                        let session_config_options =
                            std::sync::Arc::clone(&session_config_options_for_notifications);
                        async move |notification: acp::SessionNotification, _connection| {
                            if let acp::SessionUpdate::ConfigOptionUpdate(update) =
                                &notification.update
                                && let Ok(mut state) = session_config_options.write()
                            {
                                *state = update.config_options.clone();
                            }
                            if event_tx
                                .send(ConnectionEvent::SessionUpdate(notification.update))
                                .await
                            .is_err()
                            {
                                warn!("Notification channel closed, dropping update");
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_notification!(),
                )
                .on_receive_request(
                    {
                        let event_tx = event_tx.clone();
                        let cwd = approval_cwd;
                        async move |request: acp::RequestPermissionRequest,
                                    responder: sacp::Responder<acp::RequestPermissionResponse>,
                                    connection: ConnectionTo<Agent>| {
                            // Translate ACP permission request to Codex approval event.
                            let event = if let Some(patch_event) =
                                translator::permission_request_to_patch_approval_event(&request)
                            {
                                ApprovalEventType::Patch(patch_event)
                            } else {
                                let exec_event = translator::permission_request_to_approval_event(
                                    &request, &cwd,
                                );
                                ApprovalEventType::Exec(exec_event)
                            };

                            let (response_tx, response_rx) = oneshot::channel();
                            let approval = ApprovalRequest {
                                request_id: match responder.id() {
                                    serde_json::Value::String(id) => id,
                                    other => other.to_string(),
                                },
                                event,
                                acp_request: request.clone(),
                                options: request.options.clone(),
                                response_tx,
                            };

                            if event_tx
                                .send(ConnectionEvent::ApprovalRequest(approval))
                                .await
                                .is_err()
                            {
                                responder.respond(acp::RequestPermissionResponse::new(
                                    acp::RequestPermissionOutcome::Cancelled,
                                ))?;
                                return Ok(());
                            }

                            // Spawn to avoid blocking the dispatch loop.
                            connection.spawn(async move {
                                let outcome = match response_rx.await {
                                    Ok(decision) => {
                                        translator::review_decision_to_permission_outcome(
                                            decision,
                                            &request.options,
                                        )
                                    }
                                    Err(_) => {
                                        // Response channel dropped — deny.
                                        let option_id = request
                                            .options
                                            .iter()
                                            .find(|opt| {
                                                matches!(
                                                    opt.kind,
                                                    acp::PermissionOptionKind::RejectOnce
                                                        | acp::PermissionOptionKind::RejectAlways
                                                )
                                            })
                                            .map(|opt| opt.option_id.clone())
                                            .unwrap_or_else(|| {
                                                acp::PermissionOptionId::from("deny".to_string())
                                            });
                                        acp::RequestPermissionOutcome::Selected(
                                            acp::SelectedPermissionOutcome::new(option_id),
                                        )
                                    }
                                };
                                responder.respond(acp::RequestPermissionResponse::new(outcome))?;
                                Ok(())
                            })?;

                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let terminals = Arc::clone(&terminals_for_create);
                        let cwd = terminal_cwd.clone();
                        async move |request: acp::CreateTerminalRequest,
                                    responder: sacp::Responder<acp::CreateTerminalResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            match create_terminal(&request, &cwd, &terminals) {
                                Ok(response) => responder.respond(response)?,
                                Err(error) => responder.respond_with_error(error)?,
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let terminals = Arc::clone(&terminals_for_kill);
                        async move |request: acp::KillTerminalRequest,
                                    responder: sacp::Responder<acp::KillTerminalResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            match kill_terminal(&request, &terminals) {
                                Ok(response) => responder.respond(response)?,
                                Err(error) => responder.respond_with_error(error)?,
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let terminals = Arc::clone(&terminals_for_release);
                        async move |request: acp::ReleaseTerminalRequest,
                                    responder: sacp::Responder<acp::ReleaseTerminalResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            match release_terminal(&request, &terminals) {
                                Ok(response) => responder.respond(response)?,
                                Err(error) => responder.respond_with_error(error)?,
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let terminals = Arc::clone(&terminals_for_output);
                        async move |request: acp::TerminalOutputRequest,
                                    responder: sacp::Responder<acp::TerminalOutputResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            match terminal_output(&request, &terminals) {
                                Ok(response) => responder.respond(response)?,
                                Err(error) => responder.respond_with_error(error)?,
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let terminals = Arc::clone(&terminals_for_wait);
                        async move |request: acp::WaitForTerminalExitRequest,
                                    responder: sacp::Responder<acp::WaitForTerminalExitResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            match wait_for_terminal_exit(&request, &terminals) {
                                Ok(response) => responder.respond(response)?,
                                Err(error) => responder.respond_with_error(error)?,
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let event_tx = event_tx_for_write;
                        let cwd = write_cwd;
                        async move |request: acp::WriteTextFileRequest,
                                    responder: sacp::Responder<acp::WriteTextFileResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            // Emit synthetic ToolCall for TUI rendering.
                            let tool_call_id = acp::ToolCallId::from(format!(
                                "write_text_file-{}",
                                request.path.display()
                            ));
                            let title = format!("Writing {}", request.path.display());
                            let tool_call = acp::ToolCall::new(tool_call_id, title)
                                .kind(acp::ToolKind::Execute)
                                .status(acp::ToolCallStatus::Pending);
                            let _ = event_tx.try_send(ConnectionEvent::SessionUpdate(
                                acp::SessionUpdate::ToolCall(tool_call),
                            ));

                            let path = &request.path;
                            let resolved_path = if path.is_relative() {
                                cwd.join(path)
                            } else {
                                path.to_path_buf()
                            };

                            // Security: restrict writes to workspace or /tmp.
                            let allowed = if let Ok(canonical) = resolved_path.canonicalize() {
                                let in_cwd = cwd
                                    .canonicalize()
                                    .map(|c| canonical.starts_with(&c))
                                    .unwrap_or(false);
                                let in_tmp = canonical.starts_with("/tmp");
                                in_cwd || in_tmp
                            } else if let Some(parent) = resolved_path.parent() {
                                if let Ok(canonical_parent) = parent.canonicalize() {
                                    let in_cwd = cwd
                                        .canonicalize()
                                        .map(|c| canonical_parent.starts_with(&c))
                                        .unwrap_or(false);
                                    let in_tmp = canonical_parent.starts_with("/tmp");
                                    in_cwd || in_tmp
                                } else {
                                    resolved_path.starts_with(&cwd)
                                        || resolved_path.starts_with("/tmp")
                                }
                            } else {
                                false
                            };

                            if !allowed {
                                responder
                                    .respond_with_error(sacp::Error::invalid_params().data(format!(
                                    "Write restricted to working directory ({}) or /tmp. Path: {}",
                                    cwd.display(),
                                    resolved_path.display()
                                )))?;
                                return Ok(());
                            }

                            // Create parent directories if needed.
                            if let Some(parent) = resolved_path.parent()
                                && !parent.exists()
                                && let Err(e) = std::fs::create_dir_all(parent)
                            {
                                responder.respond_with_error(sacp::util::internal_error(
                                    e.to_string(),
                                ))?;
                                return Ok(());
                            }

                            match std::fs::write(&resolved_path, &request.content) {
                                Ok(()) => {
                                    responder.respond(acp::WriteTextFileResponse::new())?;
                                }
                                Err(e) => {
                                    responder.respond_with_error(sacp::util::internal_error(
                                        e.to_string(),
                                    ))?;
                                }
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .on_receive_request(
                    {
                        let event_tx = event_tx_for_read;
                        let cwd = read_cwd;
                        async move |request: acp::ReadTextFileRequest,
                                    responder: sacp::Responder<acp::ReadTextFileResponse>,
                                    _connection: ConnectionTo<Agent>| {
                            // Emit synthetic ToolCall for TUI rendering.
                            let tool_call_id = acp::ToolCallId::from(format!(
                                "read_text_file-{}",
                                request.path.display()
                            ));
                            let title = format!("Reading {}", request.path.display());
                            let tool_call = acp::ToolCall::new(tool_call_id, title)
                                .kind(acp::ToolKind::Execute)
                                .status(acp::ToolCallStatus::Pending);
                            let _ = event_tx.try_send(ConnectionEvent::SessionUpdate(
                                acp::SessionUpdate::ToolCall(tool_call),
                            ));

                            // Resolve relative paths against cwd.
                            let resolved_path = if request.path.is_relative() {
                                cwd.join(&request.path)
                            } else {
                                request.path
                            };

                            match std::fs::read_to_string(&resolved_path) {
                                Ok(content) => {
                                    responder.respond(acp::ReadTextFileResponse::new(content))?;
                                }
                                Err(e) => {
                                    responder.respond_with_error(sacp::util::internal_error(
                                        e.to_string(),
                                    ))?;
                                }
                            }
                            Ok(())
                        }
                    },
                    sacp::on_receive_request!(),
                )
                .connect_with(transport, |connection: ConnectionTo<Agent>| async move {
                    // Initialization handshake.
                    let response = connection
                        .send_request(
                            acp::InitializeRequest::new(acp::ProtocolVersion::LATEST)
                                .client_capabilities(
                                    acp::ClientCapabilities::new().fs(
                                        acp::FileSystemCapabilities::new()
                                            .read_text_file(true)
                                            .write_text_file(true),
                                    ),
                                )
                                .client_info(
                                    acp::Implementation::new("codex", env!("CARGO_PKG_VERSION"))
                                        .title("Codex CLI"),
                                ),
                        )
                        .block_task()
                        .await;

                    match response {
                        Ok(resp) => {
                            if resp.protocol_version < MINIMUM_SUPPORTED_VERSION {
                                let _ = init_tx.send(Err(anyhow::anyhow!(
                                    "ACP agent version {} is too old (minimum: {})",
                                    resp.protocol_version,
                                    MINIMUM_SUPPORTED_VERSION
                                )));
                                return Err(sacp::util::internal_error("Protocol version too old"));
                            }
                            debug!(
                                "ACP connection established (SACP v11), agent: {:?}",
                                resp.agent_info
                            );
                            let _ = init_tx.send(Ok((connection.clone(), resp.agent_capabilities)));

                            // Keep connection alive until the task is aborted.
                            futures::future::pending::<Result<(), sacp::Error>>().await
                        }
                        Err(e) => {
                            let _ = init_tx
                                .send(Err(anyhow::anyhow!("ACP initialization failed: {e}")));
                            Err(e)
                        }
                    }
                })
                .await;

            if let Err(e) = result {
                debug!("SACP connection task ended: {e}");
            }
        });

        // Wait for initialization.
        let (cx, capabilities) = init_rx
            .await
            .context("SACP connection task died during initialization")??;

        Ok(Self {
            cx,
            agent_capabilities: capabilities,
            event_rx,
            model_state: std::sync::Arc::new(std::sync::RwLock::new(AcpModelState::new())),
            session_config_options,
            connection_task,
            child,
            stderr_task,
        })
    }

    /// Create a new session with the agent.
    ///
    /// `mcp_servers` are forwarded to the agent so it can connect to CLI-configured
    /// MCP servers. Pass an empty vec for sessions that don't need MCP (e.g. hooks).
    pub async fn create_session(
        &self,
        cwd: &Path,
        mcp_servers: Vec<acp::McpServer>,
    ) -> Result<acp::SessionId> {
        let response = self
            .cx
            .send_request(acp::NewSessionRequest::new(cwd).mcp_servers(mcp_servers))
            .block_task()
            .await
            .context("Failed to create ACP session")?;

        #[cfg(feature = "unstable")]
        if let Some(ref models) = response.models
            && let Ok(mut state) = self.model_state.write()
        {
            *state = AcpModelState::from_session_model_state(models);
            debug!(
                "Model state updated: current={:?}, available={}",
                state.current_model_id,
                state.available_models.len()
            );
        }

        if let Ok(mut state) = self.session_config_options.write() {
            *state = response.config_options.clone().unwrap_or_default();
        }

        Ok(response.session_id)
    }

    /// Load (resume) an existing session.
    ///
    /// The agent replays previous session history. Updates flow through the
    /// ordered event inbox. The returned `SessionId` is the same as
    /// the input `session_id` (the LoadSessionResponse doesn't contain one).
    pub async fn load_session(&self, session_id: &str, cwd: &Path) -> Result<acp::SessionId> {
        let response = self
            .cx
            .send_request(acp::LoadSessionRequest::new(session_id.to_string(), cwd))
            .block_task()
            .await
            .context("Failed to load ACP session")?;

        #[cfg(feature = "unstable")]
        if let Some(ref models) = response.models
            && let Ok(mut state) = self.model_state.write()
        {
            *state = AcpModelState::from_session_model_state(models);
        }

        if let Ok(mut state) = self.session_config_options.write() {
            *state = response.config_options.clone().unwrap_or_default();
        }

        // The session ID from the request is reused since the response
        // doesn't contain one.
        Ok(acp::SessionId::from(session_id.to_string()))
    }

    /// Send a prompt to an existing session and receive streaming updates.
    ///
    /// Updates flow through the ordered event inbox.
    pub async fn prompt(
        &self,
        session_id: acp::SessionId,
        prompt: Vec<acp::ContentBlock>,
    ) -> Result<acp::StopReason> {
        self.cx
            .send_request(acp::PromptRequest::new(session_id, prompt))
            .block_task()
            .await
            .context("ACP prompt failed")
            .map(|r| r.stop_reason)
    }

    /// Cancel an ongoing prompt.
    pub async fn cancel(&self, session_id: &acp::SessionId) -> Result<()> {
        self.cx
            .send_notification(acp::CancelNotification::new(session_id.clone()))
            .context("Failed to cancel ACP session")
    }

    /// Get the agent's capabilities.
    pub fn capabilities(&self) -> &acp::AgentCapabilities {
        &self.agent_capabilities
    }

    /// Take ownership of the ordered ACP event receiver.
    pub fn take_event_receiver(&mut self) -> mpsc::Receiver<ConnectionEvent> {
        std::mem::replace(&mut self.event_rx, mpsc::channel(1).1)
    }

    /// Get the current model state.
    pub fn model_state(&self) -> AcpModelState {
        #[expect(
            clippy::expect_used,
            reason = "RwLock poisoning indicates a bug elsewhere"
        )]
        self.model_state
            .read()
            .expect("Model state lock poisoned")
            .clone()
    }

    /// Get the current ACP session config snapshot.
    pub fn config_options(&self) -> Vec<acp::SessionConfigOption> {
        #[expect(
            clippy::expect_used,
            reason = "RwLock poisoning indicates a bug elsewhere"
        )]
        self.session_config_options
            .read()
            .expect("Session config state lock poisoned")
            .clone()
    }

    /// Explicitly tear down the ACP subprocess and background tasks.
    ///
    /// Unlike `Drop`, this async path can wait for process termination so the
    /// child is reaped promptly during agent switches and shutdown.
    pub async fn shutdown(&self) {
        self.connection_task.abort();
        self.stderr_task.abort();

        let mut child = self.child.lock().await;

        #[cfg(unix)]
        if let Err(e) = kill_child_process_group(&mut child) {
            debug!("Failed to kill process group during shutdown: {e}");
        }

        if let Err(e) = child.kill().await {
            debug!("Failed to kill ACP agent child process during shutdown: {e}");
        }
    }

    /// Switch to a different model for the given session.
    #[cfg(feature = "unstable")]
    pub async fn set_model(
        &self,
        session_id: &acp::SessionId,
        model_id: &acp::ModelId,
    ) -> Result<()> {
        let request = acp::SetSessionModelRequest::new(session_id.clone(), model_id.clone());
        let untyped = UntypedMessage::new("session/set_model", &request)
            .context("Failed to serialize SetSessionModelRequest")?;
        self.cx
            .send_request(untyped)
            .block_task()
            .await
            .context("Failed to set ACP model")?;

        if let Ok(mut state) = self.model_state.write() {
            state.current_model_id = Some(model_id.clone());
            debug!(
                "Model state updated after switch: current={:?}",
                state.current_model_id
            );
        }

        Ok(())
    }

    /// Set the value of a session config option.
    pub async fn set_config_option(
        &self,
        session_id: &acp::SessionId,
        config_id: &acp::SessionConfigId,
        value: &acp::SessionConfigValueId,
    ) -> Result<()> {
        let response = self
            .cx
            .send_request(acp::SetSessionConfigOptionRequest::new(
                session_id.clone(),
                config_id.clone(),
                value.clone(),
            ))
            .block_task()
            .await
            .context("Failed to set ACP session config option")?;

        if let Ok(mut state) = self.session_config_options.write() {
            *state = response.config_options.clone();
        }

        Ok(())
    }
}

impl Drop for SacpConnection {
    fn drop(&mut self) {
        self.connection_task.abort();
        self.stderr_task.abort();

        let child = std::sync::Arc::clone(&self.child);
        if let Ok(mut child) = child.try_lock() {
            #[cfg(unix)]
            if let Err(e) = kill_child_process_group(&mut child) {
                debug!("Failed to kill process group: {e}");
            }

            if let Err(e) = child.start_kill() {
                debug!("Failed to kill ACP agent child process: {e}");
            }
        }
    }
}

/// Kill the entire process group to ensure grandchildren are terminated.
#[cfg(unix)]
fn kill_child_process_group(child: &mut Child) -> std::io::Result<()> {
    use std::io::ErrorKind;

    if let Some(pid) = child.id() {
        let pid = pid as libc::pid_t;

        let pgid = unsafe { libc::getpgid(pid) };
        if pgid == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::NotFound {
                return Err(err);
            }
            return Ok(());
        }

        let result = unsafe { libc::killpg(pgid, libc::SIGKILL) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::NotFound {
                return Err(err);
            }
        }
    }

    Ok(())
}

fn create_terminal(
    request: &acp::CreateTerminalRequest,
    default_cwd: &Path,
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
) -> std::result::Result<acp::CreateTerminalResponse, sacp::Error> {
    let mut command = StdCommand::new(&request.command);
    command
        .args(&request.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let cwd = request.cwd.clone().unwrap_or_else(|| default_cwd.to_path_buf());
    command.current_dir(cwd);

    for env in &request.env {
        command.env(&env.name, &env.value);
    }

    let mut child = command
        .spawn()
        .map_err(|error| sacp::util::internal_error(error.to_string()))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let terminal_id = acp::TerminalId::from(format!("terminal-{}", uuid::Uuid::new_v4()));
    let terminal = Arc::new(TerminalState::new(child, request.output_byte_limit));

    if let Some(stdout) = stdout {
        spawn_terminal_reader(stdout, Arc::clone(&terminal));
    }
    if let Some(stderr) = stderr {
        spawn_terminal_reader(stderr, Arc::clone(&terminal));
    }

    terminals
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal state lock poisoned"))?
        .insert(terminal_id.clone(), terminal);

    Ok(acp::CreateTerminalResponse::new(terminal_id))
}

fn kill_terminal(
    request: &acp::KillTerminalRequest,
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
) -> std::result::Result<acp::KillTerminalResponse, sacp::Error> {
    let terminal = terminal_state(terminals, &request.terminal_id)?;
    let mut child = terminal
        .child
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal child lock poisoned"))?;
    child
        .kill()
        .map_err(|error| sacp::util::internal_error(error.to_string()))?;
    let status = child
        .wait()
        .map_err(|error| sacp::util::internal_error(error.to_string()))?;
    drop(child);

    *terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))? =
        Some(to_terminal_exit_status(status));

    Ok(acp::KillTerminalResponse::new())
}

fn release_terminal(
    request: &acp::ReleaseTerminalRequest,
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
) -> std::result::Result<acp::ReleaseTerminalResponse, sacp::Error> {
    let terminal = terminals
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal state lock poisoned"))?
        .remove(&request.terminal_id)
        .ok_or_else(|| sacp::Error::resource_not_found(None))?;

    let should_kill = terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))?
        .is_none();
    if should_kill {
        let mut child = terminal
            .child
            .lock()
            .map_err(|_| sacp::util::internal_error("terminal child lock poisoned"))?;
        if child
            .try_wait()
            .map_err(|error| sacp::util::internal_error(error.to_string()))?
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    Ok(acp::ReleaseTerminalResponse::new())
}

fn terminal_output(
    request: &acp::TerminalOutputRequest,
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
) -> std::result::Result<acp::TerminalOutputResponse, sacp::Error> {
    let terminal = terminal_state(terminals, &request.terminal_id)?;
    refresh_terminal_exit_status(&terminal)?;

    let output = terminal
        .output
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal output lock poisoned"))?
        .clone();
    let truncated = *terminal
        .truncated
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal truncation lock poisoned"))?;
    let exit_status = terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))?
        .clone();

    Ok(acp::TerminalOutputResponse::new(output, truncated).exit_status(exit_status))
}

fn wait_for_terminal_exit(
    request: &acp::WaitForTerminalExitRequest,
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
) -> std::result::Result<acp::WaitForTerminalExitResponse, sacp::Error> {
    let terminal = terminal_state(terminals, &request.terminal_id)?;

    if let Some(exit_status) = terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))?
        .clone()
    {
        return Ok(acp::WaitForTerminalExitResponse::new(exit_status));
    }

    let status = terminal
        .child
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal child lock poisoned"))?
        .wait()
        .map_err(|error| sacp::util::internal_error(error.to_string()))?;
    let exit_status = to_terminal_exit_status(status);
    *terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))? =
        Some(exit_status.clone());

    Ok(acp::WaitForTerminalExitResponse::new(exit_status))
}

fn terminal_state(
    terminals: &Arc<StdMutex<HashMap<acp::TerminalId, Arc<TerminalState>>>>,
    terminal_id: &acp::TerminalId,
) -> std::result::Result<Arc<TerminalState>, sacp::Error> {
    terminals
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal state lock poisoned"))?
        .get(terminal_id)
        .cloned()
        .ok_or_else(|| sacp::Error::resource_not_found(None))
}

fn spawn_terminal_reader<R>(mut reader: R, terminal: Arc<TerminalState>)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => append_terminal_output(&terminal, &buf[..read]),
                Err(_) => break,
            }
        }
    });
}

fn append_terminal_output(terminal: &Arc<TerminalState>, bytes: &[u8]) {
    let chunk = String::from_utf8_lossy(bytes);
    let mut output = match terminal.output.lock() {
        Ok(output) => output,
        Err(_) => return,
    };
    output.push_str(&chunk);

    let Some(limit) = terminal.output_byte_limit else {
        return;
    };

    if output.len() <= limit as usize {
        return;
    }

    let mut truncated = match terminal.truncated.lock() {
        Ok(truncated) => truncated,
        Err(_) => return,
    };
    *truncated = true;

    while output.len() > limit as usize {
        let Some(first_char_len) = output.chars().next().map(char::len_utf8) else {
            break;
        };
        output.drain(..first_char_len);
    }
}

fn refresh_terminal_exit_status(
    terminal: &Arc<TerminalState>,
) -> std::result::Result<(), sacp::Error> {
    if terminal
        .exit_status
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))?
        .is_some()
    {
        return Ok(());
    }

    let status = terminal
        .child
        .lock()
        .map_err(|_| sacp::util::internal_error("terminal child lock poisoned"))?
        .try_wait()
        .map_err(|error| sacp::util::internal_error(error.to_string()))?;

    if let Some(status) = status {
        *terminal
            .exit_status
            .lock()
            .map_err(|_| sacp::util::internal_error("terminal exit-status lock poisoned"))? =
            Some(to_terminal_exit_status(status));
    }

    Ok(())
}

fn to_terminal_exit_status(status: std::process::ExitStatus) -> acp::TerminalExitStatus {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    #[cfg(unix)]
    let signal = status.signal().map(|signal| signal.to_string());
    #[cfg(not(unix))]
    let signal = None;

    acp::TerminalExitStatus::new()
        .exit_code(status.code().map(|code| code as u32))
        .signal(signal)
}
