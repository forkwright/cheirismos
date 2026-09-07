//! Supervisor-owned instrument configuration.
//!
//! These values originate only in local server configuration. They are never an
//! agent/API argument. The configuration fingerprint is evidence about intended
//! binding; adapter discovery records whether the connected device agrees.

use std::{collections::BTreeMap, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::SimulatorId;

use super::InstrumentError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SerialBinding {
    pub path: PathBuf,
    pub baud_rate: u32,
    pub expected_usb_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bpio2Config {
    pub serial: SerialBinding,
    pub spi_hz: u32,
    pub i2c_hz: u32,
    pub uart_baud: u32,
    pub psu_max_millivolts: u32,
    pub psu_max_milliamps: u32,
    pub pin_map: BTreeMap<String, u8>,
    pub flash_capacity_bytes: Option<u64>,
    pub flash_page_bytes: Option<u32>,
    pub flash_erase_bytes: Option<u32>,
    pub flash_four_byte_addressing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NumatoConfig {
    pub serial: SerialBinding,
    pub relay_map: BTreeMap<String, u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulatorConfig {
    /// Persistent simulator-store identity, independent of an instrument alias.
    pub identity: SimulatorId,
    pub flash_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VideoConfig {
    pub device_path: PathBuf,
    pub expected_usb_identity: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub frame_timeout_milliseconds: u64,
    pub max_frame_bytes: usize,
}

impl VideoConfig {
    pub fn validate(&self) -> Result<(), InstrumentError> {
        if self.expected_usb_identity.trim().is_empty() {
            return Err(InstrumentError::InvalidVideoConfiguration {
                detail: "expected_usb_identity must not be empty".to_owned(),
            });
        }
        if self.executable.as_os_str().is_empty() {
            return Err(InstrumentError::InvalidVideoConfiguration {
                detail: "executable must not be empty".to_owned(),
            });
        }
        if self.executable_sha256.len() != 64
            || !self.executable_sha256.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
            })
        {
            return Err(InstrumentError::InvalidVideoConfiguration {
                detail: "executable_sha256 must be 64 lowercase hexadecimal characters".to_owned(),
            });
        }
        if self.frame_timeout_milliseconds == 0 {
            return Err(InstrumentError::InvalidVideoConfiguration {
                detail: "frame_timeout_milliseconds must be non-zero".to_owned(),
            });
        }
        if self.max_frame_bytes == 0 {
            return Err(InstrumentError::InvalidVideoConfiguration {
                detail: "max_frame_bytes must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstrumentConfig {
    Bpio2(Bpio2Config),
    Numato(NumatoConfig),
    Simulator(SimulatorConfig),
    Video(VideoConfig),
}

impl InstrumentConfig {
    pub fn fingerprint(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let digest = Sha256::digest(encoded);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use super::{Bpio2Config, InstrumentConfig, SerialBinding};

    #[test]
    fn fingerprint_changes_when_commissioned_electrical_config_changes() {
        let config = |spi_hz| {
            InstrumentConfig::Bpio2(Bpio2Config {
                serial: SerialBinding {
                    path: PathBuf::from("/dev/cheirismos-bp6"),
                    baud_rate: 115_200,
                    expected_usb_identity: "usb:2a19:0001:serial".to_owned(),
                },
                spi_hz,
                i2c_hz: 100_000,
                uart_baud: 115_200,
                psu_max_millivolts: 3_300,
                psu_max_milliamps: 300,
                pin_map: BTreeMap::from([("spi_cs".to_owned(), 0)]),
                flash_capacity_bytes: Some(16 * 1024 * 1024),
                flash_page_bytes: Some(256),
                flash_erase_bytes: Some(4096),
                flash_four_byte_addressing: false,
            })
        };
        let slow = config(1_000_000)
            .fingerprint()
            .unwrap_or_else(|error| panic!("fingerprint: {error}"));
        let fast = config(8_000_000)
            .fingerprint()
            .unwrap_or_else(|error| panic!("fingerprint: {error}"));
        assert_ne!(slow, fast);
    }
}
