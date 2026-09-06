//! Private local-service configuration and credential provisioning.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::domain::{InstrumentId, PrincipalId, PrincipalRole};
use crate::service::auth::{CredentialBinding, provision_token, validate_bindings};
use crate::service::backend::DeviceBinding;

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const CONFIG_FILE: &str = "service.json";
const SOCKET_FILE: &str = "service.sock";
const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// The private, local configuration required to expose the Cheirismos service.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Root containing durable service data, the socket, and local credentials.
    pub instance_dir: PathBuf,
    /// Unix-domain socket accepted by this service.
    pub socket: PathBuf,
    /// Mode applied after binding the socket; deployments may use group access.
    #[serde(default = "default_socket_mode")]
    pub socket_mode: u32,
    /// Optional group assigned to the socket for explicitly configured local clients.
    #[serde(default)]
    pub socket_group_gid: Option<u32>,
    /// Server-owned local identities and their token digests.
    pub credentials: Vec<CredentialBinding>,
    /// Trusted intended device bindings; qualification remains in commissioned profiles.
    pub instruments: BTreeMap<InstrumentId, DeviceBinding>,
}

/// Errors while creating or loading private local-service configuration.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConfigError {
    /// Configuration serialization or parsing failed.
    #[snafu(display("service configuration JSON failed: {source}"))]
    Json { source: serde_json::Error },
    /// A private filesystem operation failed.
    #[snafu(display("service configuration I/O failed: {source}"))]
    Io { source: std::io::Error },
    /// A configured socket must be absolute and live in a private service-owned directory.
    #[snafu(display("service socket path {} is not in a trusted service-owned directory", path.display()))]
    UnsafeSocketPath {
        /// Invalid configured path.
        path: PathBuf,
        /// Declared private root.
        instance_dir: PathBuf,
    },
    /// An existing instance root is not a new empty private directory.
    #[snafu(display("service instance directory {} is not an empty private directory owned by this service", path.display()))]
    UnsafeInstanceDirectory {
        /// Existing path that cannot safely become a new instance.
        path: PathBuf,
    },
    /// The current local UID cannot be read from the supported operating system.
    #[snafu(display("cannot determine the current local UID for credential binding"))]
    CurrentUid,
    #[snafu(display("socket mode must be 0600 or 0660"))]
    InvalidSocketMode,
    /// Credential provisioning failed.
    #[snafu(display("credential provisioning failed: {source}"))]
    Credential {
        /// Underlying local credential failure.
        source: crate::service::auth::AuthenticationError,
    },
}

impl ServiceConfig {
    /// Loads a private configuration file and verifies its paths remain local.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` when parsing fails or the configuration names a
    /// socket outside a trusted service-owned directory.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(|source| ConfigError::Io { source })?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|source| ConfigError::Json { source })?;
        config.validate_paths()?;
        Ok(config)
    }

    /// Creates an empty private service instance with three distinct local roles.
    ///
    /// The method writes token plaintext only to mode-0600 files. It returns
    /// digests in configuration and never exposes tokens through this API.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if the instance cannot become a new empty private
    /// root or private files cannot be created durably. A pre-created,
    /// service-owned mode-0700 empty directory is accepted for systemd's
    /// `StateDirectory` lifecycle.
    pub fn initialize(instance_dir: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let instance_dir = prepare_instance_directory(instance_dir.into())?;
        let credential_dir = instance_dir.join("credentials");
        fs::create_dir(&credential_dir).map_err(|source| ConfigError::Io { source })?;
        fs::set_permissions(&credential_dir, fs::Permissions::from_mode(DIRECTORY_MODE))
            .map_err(|source| ConfigError::Io { source })?;

        let peer_uid = current_uid()?;
        let credentials = [
            ("operator", PrincipalRole::Operator),
            ("reviewer", PrincipalRole::Reviewer),
            ("agent", PrincipalRole::Agent),
        ]
        .into_iter()
        .map(|(name, role)| {
            let token_digest = provision_token(&credential_dir.join(format!("{name}.token")))
                .map_err(|source| ConfigError::Credential { source })?;
            Ok(CredentialBinding {
                principal: PrincipalId::try_from(name).map_err(|_| ConfigError::CurrentUid)?,
                role,
                token_digest,
                peer_uid,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
        let config = Self {
            socket: instance_dir.join(SOCKET_FILE),
            socket_mode: DEFAULT_SOCKET_MODE,
            socket_group_gid: None,
            instance_dir,
            credentials,
            instruments: BTreeMap::new(),
        };
        config.save()?;
        Ok(config)
    }

    /// Persists this configuration as a private JSON file in its instance root.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if a configuration file cannot be safely created.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.validate_paths()?;
        let encoded =
            serde_json::to_vec_pretty(self).map_err(|source| ConfigError::Json { source })?;
        let path = self.instance_dir.join(CONFIG_FILE);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)
            .map_err(|source| ConfigError::Io { source })?;
        output
            .write_all(&encoded)
            .and_then(|()| output.sync_all())
            .map_err(|source| ConfigError::Io { source })?;
        File::open(&self.instance_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ConfigError::Io { source })?;
        Ok(())
    }

    fn validate_paths(&self) -> Result<(), ConfigError> {
        if self.socket_mode != 0o600 && self.socket_mode != 0o660 {
            return Err(ConfigError::InvalidSocketMode);
        }
        validate_bindings(&self.credentials)
            .map_err(|source| ConfigError::Credential { source })?;
        if self.socket_mode == 0o660 && self.socket_group_gid.is_none() {
            return Err(ConfigError::InvalidSocketMode);
        }
        let Some(parent) = self.socket.parent() else {
            return Err(ConfigError::UnsafeSocketPath {
                path: self.socket.clone(),
                instance_dir: self.instance_dir.clone(),
            });
        };
        let metadata = fs::metadata(parent).map_err(|source| ConfigError::Io { source })?;
        let mode = metadata.permissions().mode();
        if !self.socket.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != current_uid()?
            || mode & 0o022 != 0
        {
            return Err(ConfigError::UnsafeSocketPath {
                path: self.socket.clone(),
                instance_dir: self.instance_dir.clone(),
            });
        }
        Ok(())
    }
}

fn prepare_instance_directory(instance_dir: PathBuf) -> Result<PathBuf, ConfigError> {
    match fs::symlink_metadata(&instance_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != current_uid()?
                || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
            {
                return Err(ConfigError::UnsafeInstanceDirectory { path: instance_dir });
            }
            let has_entries = fs::read_dir(&instance_dir)
                .map_err(|source| ConfigError::Io { source })?
                .next()
                .is_some();
            if has_entries {
                return Err(ConfigError::UnsafeInstanceDirectory { path: instance_dir });
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&instance_dir).map_err(|source| ConfigError::Io { source })?;
            fs::set_permissions(&instance_dir, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|source| ConfigError::Io { source })?;
        }
        Err(source) => return Err(ConfigError::Io { source }),
    }
    fs::canonicalize(instance_dir).map_err(|source| ConfigError::Io { source })
}

const fn default_socket_mode() -> u32 {
    DEFAULT_SOCKET_MODE
}

/// Returns the peer UID that a client launched by this process must present.
pub(crate) fn current_uid() -> Result<u32, ConfigError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|source| ConfigError::Io { source })?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:\t"))
        .and_then(|values| values.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(ConfigError::CurrentUid)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::tempdir;

    use super::{ConfigError, DIRECTORY_MODE, ServiceConfig};

    #[test]
    fn initialize_accepts_existing_empty_private_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary_directory = tempdir()?;
        let instance_directory = temporary_directory.path().join("instance");
        fs::create_dir(&instance_directory)?;
        fs::set_permissions(
            &instance_directory,
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )?;

        let config = ServiceConfig::initialize(&instance_directory)?;

        assert_eq!(config.instance_dir, fs::canonicalize(&instance_directory)?);
        assert!(config.instance_dir.join("service.json").is_file());
        Ok(())
    }

    #[test]
    fn initialize_never_overwrites_existing_credentials() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary_directory = tempdir()?;
        let config = ServiceConfig::initialize(temporary_directory.path().join("instance"))?;
        let credential_path = config.instance_dir.join("credentials/agent.token");
        let original_credential = fs::read(&credential_path)?;

        assert!(ServiceConfig::initialize(config.instance_dir.clone()).is_err());
        assert_eq!(fs::read(credential_path)?, original_credential);
        Ok(())
    }

    #[test]
    fn initialize_rejects_symlinked_or_non_private_existing_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary_directory = tempdir()?;
        let target_directory = temporary_directory.path().join("target");
        fs::create_dir(&target_directory)?;
        fs::set_permissions(
            &target_directory,
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )?;
        let linked_directory = temporary_directory.path().join("linked-instance");
        symlink(&target_directory, &linked_directory)?;

        assert!(matches!(
            ServiceConfig::initialize(linked_directory),
            Err(ConfigError::UnsafeInstanceDirectory { .. })
        ));

        let public_directory = temporary_directory.path().join("public-instance");
        fs::create_dir(&public_directory)?;
        fs::set_permissions(&public_directory, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            ServiceConfig::initialize(public_directory),
            Err(ConfigError::UnsafeInstanceDirectory { .. })
        ));
        Ok(())
    }
}
