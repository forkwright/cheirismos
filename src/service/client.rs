//! Local client framing for the authenticated Unix service.

use std::path::Path;

use secrecy::SecretString;
use snafu::Snafu;
use tokio::net::UnixStream;

use crate::service::api::{ServiceRequest, ServiceResponse};
use crate::service::server::{
    ClientEnvelope, ServerError, ServerReply, read_json_frame, write_json_frame,
};

/// Client-side failures while submitting a local service request.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ClientError {
    /// Reading the local token file failed.
    #[snafu(display("could not read local credential token: {source}"))]
    Credential { source: std::io::Error },
    /// Connecting to the local Unix socket failed.
    #[snafu(display("could not connect to local service: {source}"))]
    Connect { source: std::io::Error },
    /// Framing the request or reply failed.
    #[snafu(display("local service transport failed: {source}"))]
    Transport { source: ServerError },
    /// The authenticated service refused the request.
    #[snafu(display("local service refused request: {message}"))]
    Refused { message: String },
    /// The server sent an invalid reply shape.
    #[snafu(display("local service returned an empty reply"))]
    EmptyReply,
}

/// Sends one typed request using a locally stored credential token.
///
/// The client reads the token and supplied artifact paths locally; no server
/// request contains an arbitrary filesystem path.
pub async fn request(
    socket: impl AsRef<Path>,
    credential_path: impl AsRef<Path>,
    request: ServiceRequest,
) -> Result<ServiceResponse, ClientError> {
    let token = tokio::fs::read_to_string(credential_path)
        .await
        .map_err(|source| ClientError::Credential { source })?;
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|source| ClientError::Connect { source })?;
    let envelope = ClientEnvelope {
        token: SecretString::from(token),
        request,
    };
    write_json_frame(&mut stream, &envelope)
        .await
        .map_err(|source| ClientError::Transport { source })?;
    let reply: ServerReply = read_json_frame(&mut stream)
        .await
        .map_err(|source| ClientError::Transport { source })?;
    if let Some(response) = reply.response {
        return Ok(response);
    }
    if let Some(message) = reply.error {
        return Err(ClientError::Refused { message });
    }
    Err(ClientError::EmptyReply)
}
