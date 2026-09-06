//! Credentials bind a caller to a server-owned role; requests never choose authority.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::domain::{ArtifactDigest, Principal, PrincipalId, PrincipalRole};

const TOKEN_BYTES: usize = 32;
const PRIVATE_MODE: u32 = 0o600;

/// WHY: credentials remain local and are never included in structured request logs.
#[derive(Debug, Snafu)]
pub enum AuthenticationError {
    /// The caller cannot prove a configured identity.
    #[snafu(display("credential or local caller is not authorized"))]
    Unauthorized,
    /// The operator configuration assigns conflicting local identities.
    #[snafu(display("credential configuration is invalid: {reason}"))]
    InvalidConfiguration { reason: String },
    /// Provisioning could not safely create private credential material.
    #[snafu(display("credential I/O failed: {source}"))]
    Io { source: std::io::Error },
}

/// WHY: server configuration, rather than client-provided role fields, assigns authority.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    /// Stable identity used by grants and independent reviews.
    pub principal: PrincipalId,
    /// Role assigned by the operator-owned service configuration.
    pub role: PrincipalRole,
    /// SHA-256 of a random token; the plaintext is held by the corresponding client.
    pub token_digest: ArtifactDigest,
    /// UNIX peer credential required in addition to the token.
    pub peer_uid: u32,
}

/// Rejects ambiguous or shared credentials before a service accepts clients.
pub(crate) fn validate_bindings(bindings: &[CredentialBinding]) -> Result<(), AuthenticationError> {
    let mut identities = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for binding in bindings {
        if !identities.insert(&binding.principal) || !digests.insert(&binding.token_digest) {
            return Err(AuthenticationError::InvalidConfiguration {
                reason: "principal IDs and token digests must be unique".into(),
            });
        }
    }
    if bindings.is_empty() {
        return Err(AuthenticationError::InvalidConfiguration {
            reason: "at least one configured principal is required".into(),
        });
    }
    Ok(())
}

/// WHY: a request may prove identity but can never promote itself to another role.
pub fn authenticate(
    bindings: &[CredentialBinding],
    token: &str,
    peer_uid: u32,
) -> Result<Principal, AuthenticationError> {
    let digest = ArtifactDigest::sha256(token.as_bytes());
    let binding = bindings
        .iter()
        .find(|binding| binding.peer_uid == peer_uid && binding.token_digest == digest)
        .ok_or(AuthenticationError::Unauthorized)?;
    Ok(Principal {
        id: binding.principal.clone(),
        role: binding.role,
        authentication_fingerprint: binding.token_digest.clone(),
    })
}

/// WHY: initialization creates unpredictable role-specific credentials without printing them.
pub fn provision_token(path: &Path) -> Result<ArtifactDigest, AuthenticationError> {
    let mut random = [0_u8; TOKEN_BYTES];
    File::open("/dev/urandom")
        .and_then(|mut entropy| entropy.read_exact(&mut random))
        .map_err(|source| AuthenticationError::Io { source })?;
    let token = hex::encode(random);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_MODE)
        .open(path)
        .map_err(|source| AuthenticationError::Io { source })?;
    output
        .write_all(token.as_bytes())
        .and_then(|()| output.sync_all())
        .map_err(|source| AuthenticationError::Io { source })?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| AuthenticationError::Io { source })?;
    }
    Ok(ArtifactDigest::sha256(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_cannot_select_role_or_different_peer() -> Result<(), Box<dyn std::error::Error>> {
        let bindings = vec![CredentialBinding {
            principal: PrincipalId::try_from("agent")?,
            role: PrincipalRole::Agent,
            token_digest: ArtifactDigest::sha256(b"secret"),
            peer_uid: 101,
        }];
        let caller = authenticate(&bindings, "secret", 101)?;
        assert_eq!(caller.role, PrincipalRole::Agent);
        assert!(authenticate(&bindings, "secret", 102).is_err());
        assert!(authenticate(&bindings, "wrong", 101).is_err());
        Ok(())
    }

    #[test]
    fn provisioning_never_overwrites_existing_credentials() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator.token");
        let digest = provision_token(&path)?;
        let token = std::fs::read_to_string(&path)?;
        assert_eq!(digest, ArtifactDigest::sha256(token.as_bytes()));
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            PRIVATE_MODE
        );
        assert!(provision_token(&path).is_err());
        assert_eq!(token, std::fs::read_to_string(path)?);
        Ok(())
    }
}
