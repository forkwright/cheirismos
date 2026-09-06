use std::{collections::BTreeSet, fs};

use serde_json::json;

use crate::domain::{ArtifactDigest, Observation};
use crate::instruments::InstrumentConfig;
use crate::supervisor::BackendError;

use super::{Connected, DeviceBinding, MAX_EVIDENCE_BYTES, malformed, transport};

pub(super) fn validate_config(config: &InstrumentConfig) -> Result<(), BackendError> {
    match config {
        InstrumentConfig::Bpio2(config) => {
            if config.spi_hz == 0 || config.i2c_hz == 0 || config.uart_baud == 0 {
                return Err(malformed("bus speeds must be positive"));
            }
            if config.pin_map.values().any(|pin| *pin >= 8)
                || config.psu_max_milliamps > u32::from(u16::MAX)
            {
                return Err(malformed(
                    "instrument electrical configuration exceeds protocol limits",
                ));
            }
        }
        InstrumentConfig::Numato(config) if config.relay_map.values().any(|relay| *relay >= 4) => {
            return Err(malformed(
                "Numato relay map is outside the four-channel module",
            ));
        }
        InstrumentConfig::Simulator(config)
            if config.flash_bytes == 0 || config.flash_bytes > MAX_EVIDENCE_BYTES =>
        {
            return Err(malformed("simulator flash capacity is outside 1..=64MiB"));
        }
        InstrumentConfig::Video(config) => {
            crate::instruments::VideoAdapter::new(config).map_err(transport)?;
        }
        _ => {}
    }
    let serial = match config {
        InstrumentConfig::Bpio2(config) => Some(&config.serial),
        InstrumentConfig::Numato(config) => Some(&config.serial),
        _ => None,
    };
    if let Some(serial) = serial {
        if !serial.path.is_absolute() || serial.baud_rate == 0 {
            return Err(malformed(
                "serial configuration requires an absolute bound path and positive baud rate",
            ));
        }
        canonical_serial_usb_identity(&serial.expected_usb_identity)?;
    }
    if let InstrumentConfig::Video(config) = config {
        canonical_video_usb_identity(&config.expected_usb_identity)?;
    }
    Ok(())
}

/// The configured stable physical key. It deliberately excludes paths, aliases,
/// firmware versions, and electrical configuration.
pub(super) fn configured_physical_identity(
    config: &InstrumentConfig,
) -> Result<ArtifactDigest, BackendError> {
    validate_config(config)?;
    let key = match config {
        InstrumentConfig::Bpio2(config) => {
            canonical_serial_usb_identity(&config.serial.expected_usb_identity)?
        }
        InstrumentConfig::Numato(config) => {
            canonical_serial_usb_identity(&config.serial.expected_usb_identity)?
        }
        InstrumentConfig::Simulator(config) => format!("simulator:{}", config.identity.as_str()),
        InstrumentConfig::Video(config) => {
            canonical_video_usb_identity(&config.expected_usb_identity)?
        }
    };
    Ok(ArtifactDigest::sha256(
        format!("cheirismos:physical-identity:v1:{key}").as_bytes(),
    ))
}

/// Reject aliases that name one stable physical instrument more than once.
pub(super) fn validate_unique_physical_identities<'a>(
    configs: impl IntoIterator<Item = &'a InstrumentConfig>,
) -> Result<(), BackendError> {
    let mut identities = BTreeSet::new();
    for config in configs {
        let identity = configured_physical_identity(config)?;
        if !identities.insert(identity) {
            return Err(malformed(
                "multiple configured aliases resolve to the same physical instrument",
            ));
        }
    }
    Ok(())
}

/// Re-observe a serial USB identity and prove it is the configured physical key.
pub(super) fn verify_usb(config: &InstrumentConfig) -> Result<ArtifactDigest, BackendError> {
    let configured = configured_physical_identity(config)?;
    let serial = match config {
        InstrumentConfig::Bpio2(config) => &config.serial,
        InstrumentConfig::Numato(config) => &config.serial,
        _ => return Ok(configured),
    };
    let expected_path = fs::canonicalize(&serial.path).map_err(transport)?;
    let ports = tokio_serial::available_ports().map_err(transport)?;
    let mut identities = Vec::new();
    for port in ports {
        if fs::canonicalize(&port.port_name).ok().as_ref() != Some(&expected_path) {
            continue;
        }
        if let tokio_serial::SerialPortType::UsbPort(usb) = port.port_type {
            let serial_number = usb
                .serial_number
                .filter(|serial| !serial.is_empty())
                .ok_or_else(|| malformed("bound USB instrument has no serial identity"))?;
            identities.push(format!(
                "usb:{:04x}:{:04x}:{serial_number}",
                usb.vid, usb.pid
            ));
        }
    }
    let [observed_identity] = identities.as_slice() else {
        return Err(malformed(
            "bound serial path does not resolve to the unique commissioned USB identity",
        ));
    };
    if observed_identity != &serial.expected_usb_identity {
        return Err(malformed(
            "bound serial path does not resolve to the unique commissioned USB identity",
        ));
    }
    let observed = ArtifactDigest::sha256(
        format!(
            "cheirismos:physical-identity:v1:{}",
            canonical_serial_usb_identity(observed_identity)?
        )
        .as_bytes(),
    );
    if observed != configured {
        return Err(malformed(
            "observed USB identity differs from configured physical identity",
        ));
    }
    Ok(observed)
}

pub(super) async fn observe(
    binding: &DeviceBinding,
    connected: &mut Connected,
) -> Result<Observation, BackendError> {
    let configured_physical_identity = configured_physical_identity(&binding.config)?;
    let observed_serial_physical_identity = verify_usb(&binding.config)?;
    let configuration_digest =
        ArtifactDigest::sha256(&serde_json::to_vec(binding).map_err(malformed)?);
    let (identity, status, observed_physical_identity) = match connected {
        Connected::Bpio2(adapter) => {
            let discovery = adapter.identify().await.map_err(transport)?;
            if discovery.flatbuffer_major != 2 {
                return Err(malformed("unsupported BPIO2 protocol major"));
            }
            let identity = json!({
                "protocol": [discovery.flatbuffer_major, discovery.flatbuffer_minor],
                "hardware": [discovery.hardware_major, discovery.hardware_minor],
                "firmware": [discovery.firmware_major, discovery.firmware_minor],
                "firmware_git_hash": discovery.firmware_git_hash,
                "firmware_date": discovery.firmware_date,
                "modes_available": discovery.modes_available,
            });
            let status = json!({
                "mode": discovery.mode_current,
                "max_packet_bytes": discovery.max_packet_bytes,
                "max_write_bytes": discovery.max_write_bytes,
                "max_read_bytes": discovery.max_read_bytes,
                "psu_enabled": discovery.psu_enabled,
                "psu_set_millivolts": discovery.psu_set_millivolts,
                "psu_set_milliamps": discovery.psu_set_milliamps,
                "psu_measured_millivolts": discovery.psu_measured_millivolts,
                "psu_measured_milliamps": discovery.psu_measured_milliamps,
                "adc_millivolts": discovery.adc_millivolts,
                "io_direction": discovery.io_direction,
                "io_value": discovery.io_value,
            });
            (identity, status, observed_serial_physical_identity.clone())
        }
        Connected::Numato(adapter) => {
            let identity = adapter.identify().await.map_err(transport)?;
            (
                json!({"firmware":identity.firmware,"module_id":identity.module_id}),
                json!({"physical_contacts_observed":false}),
                observed_serial_physical_identity.clone(),
            )
        }
        Connected::Simulator(simulator) => (
            json!({"implementation":"cheirismos-simulator-v1","flash_bytes":simulator.observe().flash_bytes}),
            json!(simulator.observe()),
            configured_physical_identity.clone(),
        ),
        Connected::Video(adapter) => {
            let identity = adapter.inspect().map_err(transport)?;
            let observed = video_physical_identity(&identity.usb_identity)?;
            (
                json!({"usb_identity":identity.usb_identity}),
                json!({"capture":"uvc_v4l2","interpretation":null}),
                observed,
            )
        }
    };
    if observed_physical_identity != configured_physical_identity {
        return Err(malformed(
            "observed instrument physical identity differs from configured stable identity",
        ));
    }
    let fingerprint = ArtifactDigest::sha256(
        &serde_json::to_vec(
            &json!({"configuration":configuration_digest,"observed_identity":identity}),
        )
        .map_err(malformed)?,
    );
    Ok(Observation {
        captured_at: jiff::Timestamp::now().to_string(),
        source_fingerprint: fingerprint.clone(),
        body: json!({"instrument_fingerprint":fingerprint,"physical_identity":configured_physical_identity,"configuration_digest":configuration_digest,"observed_identity":identity,"status":status,"hardware_qualification":"separate_commissioning_evidence_required"}),
        evidence: None,
    })
}

fn canonical_serial_usb_identity(value: &str) -> Result<String, BackendError> {
    let Some(raw) = value.strip_prefix("usb:") else {
        return Err(malformed("serial USB identity must start with usb:"));
    };
    canonical_usb_identity(raw)
}

fn canonical_video_usb_identity(value: &str) -> Result<String, BackendError> {
    canonical_usb_identity(value)
}

fn video_physical_identity(value: &str) -> Result<ArtifactDigest, BackendError> {
    Ok(ArtifactDigest::sha256(
        format!(
            "cheirismos:physical-identity:v1:{}",
            canonical_video_usb_identity(value)?
        )
        .as_bytes(),
    ))
}

fn canonical_usb_identity(value: &str) -> Result<String, BackendError> {
    let mut parts = value.splitn(3, ':');
    let (Some(vid), Some(pid), Some(serial)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(malformed("USB identity must be vid:pid:serial"));
    };
    if !is_lower_hex_word(vid)
        || !is_lower_hex_word(pid)
        || serial.is_empty()
        || is_unknown_serial(serial)
    {
        return Err(malformed(
            "USB identity requires lowercase four-hex VID:PID and a known serial",
        ));
    }
    Ok(format!("usb:{vid}:{pid}:{serial}"))
}

fn is_lower_hex_word(value: &str) -> bool {
    value.len() == 4
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_unknown_serial(serial: &str) -> bool {
    matches!(
        serial.to_ascii_lowercase().as_str(),
        "unknown" | "none" | "null" | "n/a"
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use crate::instruments::{Bpio2Config, SerialBinding};

    use super::*;

    fn bpio(usb_identity: &str, spi_hz: u32) -> InstrumentConfig {
        InstrumentConfig::Bpio2(Bpio2Config {
            serial: SerialBinding {
                path: PathBuf::from("/dev/cheirismos-bp6"),
                baud_rate: 115_200,
                expected_usb_identity: usb_identity.to_owned(),
            },
            spi_hz,
            i2c_hz: 100_000,
            uart_baud: 115_200,
            psu_max_millivolts: 3_300,
            psu_max_milliamps: 300,
            pin_map: BTreeMap::from([("cs".to_owned(), 0)]),
            flash_capacity_bytes: Some(16 * 1024 * 1024),
            flash_page_bytes: Some(256),
            flash_erase_bytes: Some(4_096),
            flash_four_byte_addressing: false,
        })
    }

    #[test]
    fn aliases_with_one_usb_identity_have_one_stable_lease_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = bpio("usb:2a19:0001:bp6-a", 1_000_000);
        let reconfigured_alias = bpio("usb:2a19:0001:bp6-a", 8_000_000);
        let first_identity = configured_physical_identity(&first)?;
        let alias_identity = configured_physical_identity(&reconfigured_alias)?;
        assert_eq!(
            first_identity, alias_identity,
            "configuration changes must not alter the stable lease key"
        );
        let error = match validate_unique_physical_identities([&first, &reconfigured_alias]) {
            Ok(()) => return Err("same USB identity was accepted under two aliases".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("same physical instrument"));
        Ok(())
    }

    #[test]
    fn distinct_usb_devices_have_distinct_stable_lease_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = bpio("usb:2a19:0001:bp6-a", 1_000_000);
        let second = bpio("usb:2a19:0001:bp6-b", 1_000_000);
        let first_identity = configured_physical_identity(&first)?;
        let second_identity = configured_physical_identity(&second)?;
        assert_ne!(
            first_identity, second_identity,
            "distinct USB serials must produce distinct lease keys"
        );
        validate_unique_physical_identities([&first, &second])?;
        Ok(())
    }

    #[test]
    fn rejects_unknown_or_missing_usb_serials() -> Result<(), Box<dyn std::error::Error>> {
        for identity in ["usb:2a19:0001:", "usb:2a19:0001:UNKNOWN"] {
            let error = match configured_physical_identity(&bpio(identity, 1_000_000)) {
                Ok(_) => {
                    return Err(format!("unusable USB serial {identity:?} was accepted").into());
                }
                Err(error) => error,
            };
            assert!(error.to_string().contains("known serial"));
        }
        Ok(())
    }
}
