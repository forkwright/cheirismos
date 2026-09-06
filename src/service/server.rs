//! Bounded authenticated Unix-domain socket service transport.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use snafu::Snafu;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

use crate::service::api::{ApiError, ServiceApi, ServiceRequest, ServiceResponse};
use crate::service::auth::authenticate;
use crate::service::config::ServiceConfig;

/// Largest accepted or emitted JSON frame, including its request envelope.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_CLIENTS: usize = 8;

/// A local client proof and closed typed request.
///
/// This type intentionally does not implement `Debug`: its token must never
/// reach logs or panic diagnostics.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEnvelope {
    /// Token held in zeroizing memory and exposed only while writing or authenticating a frame.
    pub token: SecretString,
    /// Request evaluated under the principal selected by the server.
    pub request: ServiceRequest,
}

impl Serialize for ClientEnvelope {
    /// Serializes the credential only while forming the authenticated local wire frame.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut envelope = serializer.serialize_struct("ClientEnvelope", 2)?;
        envelope.serialize_field("token", self.token.expose_secret())?;
        envelope.serialize_field("request", &self.request)?;
        envelope.end()
    }
}

/// A framed local-service reply with no credential material or artifact bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerReply {
    /// Successful typed response, when the request was accepted.
    pub response: Option<ServiceResponse>,
    /// Sanitized service error text, when the request was refused.
    pub error: Option<String>,
}

/// Transport failures distinct from authenticated API refusals.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ServerError {
    /// A Unix-domain socket operation failed.
    #[snafu(display("Unix service socket I/O failed: {source}"))]
    Io { source: std::io::Error },
    /// A frame did not fit the declared bounded protocol.
    #[snafu(display("service frame size {actual} exceeds maximum {maximum}"))]
    FrameTooLarge {
        /// Received or emitted frame length.
        actual: usize,
        /// Configured frame cap.
        maximum: usize,
    },
    /// A frame could not be decoded as one strict JSON value.
    #[snafu(display("service frame JSON failed: {source}"))]
    Json { source: serde_json::Error },
    /// A client exceeded a bounded service I/O deadline.
    #[snafu(display("service client exceeded its I/O deadline"))]
    Timeout,
    #[snafu(display("another Cheirismos supervisor already owns this instance"))]
    AlreadyRunning,
    /// Refusing to delete an arbitrary file makes stale socket cleanup safe.
    #[snafu(display("configured socket path exists but is not a Unix socket"))]
    SocketPathOccupied,
}

/// Owns the Unix listener and authenticated request dispatch loop.
pub struct UnixServiceServer {
    config: ServiceConfig,
    api: Arc<ServiceApi>,
    daemon_lock: Option<DaemonLock>,
}

impl UnixServiceServer {
    /// Creates a server using a fully configured backend-backed API facade.
    #[must_use]
    pub fn new(config: ServiceConfig, api: Arc<ServiceApi>) -> Self {
        Self {
            config,
            api,
            daemon_lock: None,
        }
    }

    /// Creates a server with a lock acquired before opening any durable state.
    #[must_use]
    pub fn with_daemon_lock(
        config: ServiceConfig,
        api: Arc<ServiceApi>,
        daemon_lock: DaemonLock,
    ) -> Self {
        Self {
            config,
            api,
            daemon_lock: Some(daemon_lock),
        }
    }

    /// Binds the configured private socket and serves connections until cancelled.
    ///
    /// Each connection gets a bounded request deadline. Accepted physical work
    /// is owned by the API's detached task, not by this connection.
    ///
    /// # Errors
    ///
    /// Returns `ServerError` when binding or accepting the Unix socket fails.
    pub async fn serve(&self) -> Result<(), ServerError> {
        let _fallback_lock = self
            .daemon_lock
            .is_none()
            .then(|| DaemonLock::acquire(&self.config.instance_dir))
            .transpose()?;
        if let Ok(metadata) = fs::symlink_metadata(&self.config.socket) {
            if metadata.file_type().is_socket() {
                fs::remove_file(&self.config.socket)
                    .map_err(|source| ServerError::Io { source })?;
            } else {
                return Err(ServerError::SocketPathOccupied);
            }
        }
        let listener =
            UnixListener::bind(&self.config.socket).map_err(|source| ServerError::Io { source })?;
        if let Some(group_gid) = self.config.socket_group_gid {
            rustix::fs::chown(
                &self.config.socket,
                None,
                Some(rustix::fs::Gid::from_raw(group_gid)),
            )
            .map_err(|source| ServerError::Io {
                source: source.into(),
            })?;
        }
        fs::set_permissions(
            &self.config.socket,
            fs::Permissions::from_mode(self.config.socket_mode),
        )
        .map_err(|source| ServerError::Io { source })?;
        let capacity = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|source| ServerError::Io { source })?;
            let permit = Arc::clone(&capacity)
                .acquire_owned()
                .await
                .map_err(|source| ServerError::Io {
                    source: std::io::Error::other(source),
                })?;
            let api = Arc::clone(&self.api);
            let bindings = self.config.credentials.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = serve_client(stream, &bindings, api).await {
                    tracing::warn!(error = %error, "local service client ended with transport failure");
                }
            });
        }
    }
}

/// An advisory process-lifetime lock that releases automatically after a crash.
/// Process-lifetime singleton guard held before the SQLite-backed supervisor opens.
pub struct DaemonLock {
    _file: File,
}

impl DaemonLock {
    /// Acquires this instance's singleton lock before durable state is opened.
    pub fn acquire(instance_dir: &Path) -> Result<Self, ServerError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(instance_dir.join("supervisor.lock"))
            .map_err(|source| ServerError::Io { source })?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                let source: std::io::Error = error.into();
                if source.kind() == std::io::ErrorKind::WouldBlock {
                    ServerError::AlreadyRunning
                } else {
                    ServerError::Io { source }
                }
            },
        )?;
        Ok(Self { _file: file })
    }
}

/// Reads one strict request from a connected client and returns one reply.
///
/// This is public for in-process integration tests; production callers use
/// `UnixServiceServer::serve`.
pub async fn serve_client(
    mut stream: UnixStream,
    bindings: &[crate::service::auth::CredentialBinding],
    api: Arc<ServiceApi>,
) -> Result<(), ServerError> {
    let peer_uid = stream
        .peer_cred()
        .map_err(|source| ServerError::Io { source })?
        .uid();
    let envelope: ClientEnvelope = read_json_frame(&mut stream).await?;
    let reply = match authenticate(bindings, envelope.token.expose_secret(), peer_uid) {
        Ok(principal) => match api.handle(principal, envelope.request).await {
            Ok(response) => ServerReply {
                response: Some(response),
                error: None,
            },
            Err(error) => failure_reply(error),
        },
        Err(error) => ServerReply {
            response: None,
            error: Some(error.to_string()),
        },
    };
    write_json_frame(&mut stream, &reply).await
}

/// Reads a maximum-64MiB JSON message using the shared local protocol.
pub async fn read_json_frame<T>(stream: &mut UnixStream) -> Result<T, ServerError>
where
    T: for<'de> Deserialize<'de>,
{
    let length = timeout(REQUEST_TIMEOUT, stream.read_u32())
        .await
        .map_err(|_| ServerError::Timeout)?
        .map_err(|source| ServerError::Io { source })?;
    let length = usize::try_from(length).map_err(|_| ServerError::FrameTooLarge {
        actual: usize::MAX,
        maximum: MAX_FRAME_BYTES,
    })?;
    if length > MAX_FRAME_BYTES {
        return Err(ServerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut bytes = vec![0_u8; length];
    timeout(REQUEST_TIMEOUT, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| ServerError::Timeout)?
        .map_err(|source| ServerError::Io { source })?;
    serde_json::from_slice(&bytes).map_err(|source| ServerError::Json { source })
}

/// Emits a maximum-64MiB JSON message using the shared local protocol.
pub async fn write_json_frame<T>(stream: &mut UnixStream, value: &T) -> Result<(), ServerError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).map_err(|source| ServerError::Json { source })?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ServerError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ServerError::FrameTooLarge {
        actual: bytes.len(),
        maximum: MAX_FRAME_BYTES,
    })?;
    timeout(REQUEST_TIMEOUT, stream.write_u32(length))
        .await
        .map_err(|_| ServerError::Timeout)?
        .map_err(|source| ServerError::Io { source })?;
    timeout(REQUEST_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| ServerError::Timeout)?
        .map_err(|source| ServerError::Io { source })?;
    timeout(REQUEST_TIMEOUT, stream.flush())
        .await
        .map_err(|_| ServerError::Timeout)?
        .map_err(|source| ServerError::Io { source })?;
    Ok(())
}

fn failure_reply(error: ApiError) -> ServerReply {
    ServerReply {
        response: None,
        error: Some(error.to_string()),
    }
}

/// Returns the token path conventional `ServiceConfig::initialize` creates.
#[must_use]
pub fn credential_path(instance_dir: &Path, role: &str) -> std::path::PathBuf {
    instance_dir
        .join("credentials")
        .join(format!("{role}.token"))
}
