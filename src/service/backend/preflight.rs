//! Frozen-configuration validation before an admitted operation reaches hardware.
//!
//! This module only checks the reviewed operation against its supervisor-owned
//! binding and verified artifact bytes. It does not open instruments, inspect a
//! device, or mutate simulator state.

use crate::domain::{ArtifactDigest, Operation};
use crate::instruments::{AddressMode, FlashGeometry, InstrumentConfig, VideoAdapter};
use crate::supervisor::{ArtifactResolver, BackendError};

use super::{DeviceBinding, MAX_EVIDENCE_BYTES, malformed, source_bytes, transport};

const BPIO_MAX_REQUEST_BYTES: usize = u16::MAX as usize;
const I2C_ADDRESS_BYTES: usize = 1;

/// Validate a single frozen operation before the backend performs any I/O.
pub(super) fn validate(
    binding: &DeviceBinding,
    operation: &Operation,
    artifacts: &dyn ArtifactResolver,
) -> Result<(), BackendError> {
    match &binding.config {
        InstrumentConfig::Bpio2(config) => validate_bpio(binding, config, operation, artifacts),
        InstrumentConfig::Numato(config) => validate_numato(config, operation),
        InstrumentConfig::Simulator(config) => {
            validate_simulator(config.flash_bytes, operation, artifacts)
        }
        InstrumentConfig::Video(config) => validate_video(config, operation),
    }
}

fn validate_bpio(
    binding: &DeviceBinding,
    config: &crate::instruments::Bpio2Config,
    operation: &Operation,
    artifacts: &dyn ArtifactResolver,
) -> Result<(), BackendError> {
    if config.spi_hz == 0 || config.i2c_hz == 0 || config.uart_baud == 0 {
        return Err(malformed("BPIO2 configured bus speeds must be positive"));
    }
    if config.pin_map.values().any(|pin| *pin >= 8)
        || config.psu_max_milliamps > u32::from(u16::MAX)
    {
        return Err(malformed(
            "BPIO2 electrical configuration exceeds protocol limits",
        ));
    }
    match operation {
        Operation::InstrumentStatus { .. } => Ok(()),
        Operation::SpiTransfer { tx, rx_bytes, .. } => {
            nonempty_exchange(tx.len(), *rx_bytes, "SPI transfer")?;
            bounded_bytes(tx.len(), "SPI write")?;
            bounded_optional_capture(*rx_bytes, "SPI capture")
        }
        Operation::I2cTransfer {
            address,
            tx,
            rx_bytes,
            ..
        } => {
            if *address > 0x7f {
                return Err(malformed("I2C address must be a seven-bit value"));
            }
            nonempty_exchange(tx.len(), *rx_bytes, "I2C transfer")?;
            bounded_bytes(tx.len(), "I2C write")?;
            bounded_optional_capture(*rx_bytes, "I2C capture")?;
            let request_write_bytes = tx
                .len()
                .checked_add(I2C_ADDRESS_BYTES)
                .ok_or_else(|| malformed("I2C write length overflows BPIO2 request bounds"))?;
            if request_write_bytes > BPIO_MAX_REQUEST_BYTES
                || usize::try_from(*rx_bytes).map_err(malformed)? > BPIO_MAX_REQUEST_BYTES
            {
                return Err(malformed(
                    "I2C transfer exceeds one unsplittable BPIO2 u16 request",
                ));
            }
            Ok(())
        }
        Operation::I2cScan { .. } => Ok(()),
        Operation::UartCapture { max_bytes, .. } => bounded_capture(*max_bytes, "UART capture"),
        Operation::UartTransmit { bytes, .. } => {
            if bytes.is_empty() {
                return Err(malformed("UART transmit must contain at least one byte"));
            }
            bounded_bytes(bytes.len(), "UART transmit")
        }
        Operation::GpioSet { pin, .. } => {
            let pin = u8::try_from(*pin).map_err(malformed)?;
            if pin >= 8 || !config.pin_map.values().any(|configured| *configured == pin) {
                return Err(malformed(
                    "GPIO pin is outside the configured fixture pin map",
                ));
            }
            Ok(())
        }
        Operation::AdcRead { channel, .. } => {
            // BPIO status reports millivolts for the eight-bit IO pin bank.
            if *channel >= 8 {
                return Err(malformed("ADC channel is outside the BPIO IO pin range"));
            }
            Ok(())
        }
        Operation::PsuSet {
            millivolts,
            milliamps,
            ..
        } => {
            if *millivolts > config.psu_max_millivolts
                || *milliamps > config.psu_max_milliamps
                || *milliamps > u32::from(u16::MAX)
            {
                return Err(malformed(
                    "PSU request exceeds configured electrical or protocol limits",
                ));
            }
            Ok(())
        }
        Operation::FlashIdentify { .. } => Ok(()),
        Operation::FlashRead { offset, length, .. } => {
            let geometry = qualified_bpio_geometry(config)?;
            bounded_capture(*length, "flash read")?;
            require_flash_identity(binding)?;
            geometry.validate_range(*offset, *length).map_err(malformed)
        }
        Operation::FlashErase { offset, length, .. } => {
            let geometry = qualified_bpio_geometry(config)?;
            nonzero(*length, "flash erase")?;
            bounded_capture(*length, "flash erase")?;
            require_flash_identity(binding)?;
            geometry.validate_erase(*offset, *length).map_err(malformed)
        }
        Operation::FlashWrite {
            offset,
            source,
            length,
            ..
        }
        | Operation::FlashVerify {
            offset,
            source,
            length,
            ..
        } => {
            let geometry = qualified_bpio_geometry(config)?;
            nonzero(*length, "flash write/verify")?;
            bounded_capture(*length, "flash write/verify")?;
            require_flash_identity(binding)?;
            geometry
                .validate_range(*offset, *length)
                .map_err(malformed)?;
            exact_source(artifacts, source, *length)
        }
        _ => Err(unsupported("BPIO2", operation)),
    }
}

fn validate_numato(
    config: &crate::instruments::NumatoConfig,
    operation: &Operation,
) -> Result<(), BackendError> {
    if config.relay_map.values().any(|relay| *relay >= 4) {
        return Err(malformed(
            "Numato relay map is outside the four-channel module",
        ));
    }
    match operation {
        Operation::InstrumentStatus { .. } => Ok(()),
        Operation::RelaySet { relay, .. } | Operation::RelayRead { relay, .. } => {
            let relay = u8::try_from(*relay).map_err(malformed)?;
            if relay >= 4
                || !config
                    .relay_map
                    .values()
                    .any(|configured| *configured == relay)
            {
                return Err(malformed(
                    "relay is outside the configured Numato fixture map",
                ));
            }
            Ok(())
        }
        _ => Err(unsupported("Numato", operation)),
    }
}

fn validate_simulator(
    flash_bytes: usize,
    operation: &Operation,
    artifacts: &dyn ArtifactResolver,
) -> Result<(), BackendError> {
    if flash_bytes == 0 || flash_bytes > MAX_EVIDENCE_BYTES {
        return Err(malformed("simulator flash capacity is outside 1..=64MiB"));
    }
    match operation {
        Operation::InstrumentStatus { .. } | Operation::FlashIdentify { .. } => Ok(()),
        Operation::RelaySet { relay, .. } | Operation::RelayRead { relay, .. } => {
            if *relay >= 4 {
                return Err(malformed("simulator relay is outside 0..4"));
            }
            Ok(())
        }
        Operation::FlashRead { offset, length, .. } => {
            bounded_capture(*length, "simulator flash read")?;
            simulator_range(flash_bytes, *offset, *length)
        }
        Operation::FlashErase { offset, length, .. } => {
            nonzero(*length, "simulator flash erase")?;
            bounded_capture(*length, "simulator flash erase")?;
            simulator_range(flash_bytes, *offset, *length)
        }
        Operation::FlashWrite {
            offset,
            source,
            length,
            ..
        }
        | Operation::FlashVerify {
            offset,
            source,
            length,
            ..
        } => {
            nonzero(*length, "simulator flash write/verify")?;
            bounded_capture(*length, "simulator flash write/verify")?;
            simulator_range(flash_bytes, *offset, *length)?;
            exact_source(artifacts, source, *length)
        }
        _ => Err(unsupported("simulator", operation)),
    }
}

fn validate_video(
    config: &crate::instruments::VideoConfig,
    operation: &Operation,
) -> Result<(), BackendError> {
    VideoAdapter::new(config).map_err(transport)?;
    if config.max_frame_bytes > MAX_EVIDENCE_BYTES {
        return Err(malformed(
            "video frame capacity exceeds 64MiB evidence limit",
        ));
    }
    match operation {
        Operation::InstrumentStatus { .. } | Operation::VideoCapture { .. } => Ok(()),
        _ => Err(unsupported("video", operation)),
    }
}

fn qualified_bpio_geometry(
    config: &crate::instruments::Bpio2Config,
) -> Result<FlashGeometry, BackendError> {
    let (Some(capacity), Some(page), Some(erase)) = (
        config.flash_capacity_bytes,
        config.flash_page_bytes,
        config.flash_erase_bytes,
    ) else {
        return Err(malformed(
            "flash requires commissioned capacity, page, and erase geometry",
        ));
    };
    let mode = if config.flash_four_byte_addressing {
        AddressMode::FourByte
    } else {
        AddressMode::ThreeByte
    };
    FlashGeometry::try_new(capacity, page, erase, mode).map_err(malformed)
}

fn require_flash_identity(binding: &DeviceBinding) -> Result<(), BackendError> {
    if binding.flash_identity.is_none() {
        return Err(malformed(
            "flash operation requires commissioned JEDEC and SFDP identity",
        ));
    }
    Ok(())
}

fn exact_source(
    artifacts: &dyn ArtifactResolver,
    source: &ArtifactDigest,
    length: u32,
) -> Result<(), BackendError> {
    source_bytes(artifacts, source, length).map(|_| ())
}

fn simulator_range(flash_bytes: usize, offset: u64, length: u32) -> Result<(), BackendError> {
    let capacity = u64::try_from(flash_bytes).map_err(malformed)?;
    let end = offset
        .checked_add(u64::from(length))
        .ok_or_else(|| malformed("simulator flash range overflows"))?;
    if end > capacity {
        return Err(malformed(
            "simulator flash range exceeds configured capacity",
        ));
    }
    Ok(())
}

fn nonempty_exchange(write_bytes: usize, read_bytes: u32, kind: &str) -> Result<(), BackendError> {
    if write_bytes == 0 && read_bytes == 0 {
        return Err(malformed(format!(
            "{kind} must write or capture at least one byte"
        )));
    }
    Ok(())
}

fn nonzero(length: u32, kind: &str) -> Result<(), BackendError> {
    if length == 0 {
        return Err(malformed(format!("{kind} must capture at least one byte")));
    }
    Ok(())
}

fn bounded_capture(length: u32, kind: &str) -> Result<(), BackendError> {
    nonzero(length, kind)?;
    bounded_bytes(usize::try_from(length).map_err(malformed)?, kind)
}

fn bounded_optional_capture(length: u32, kind: &str) -> Result<(), BackendError> {
    if length == 0 {
        return Ok(());
    }
    bounded_capture(length, kind)
}

fn bounded_bytes(length: usize, kind: &str) -> Result<(), BackendError> {
    if length > MAX_EVIDENCE_BYTES {
        return Err(malformed(format!("{kind} exceeds 64MiB evidence limit")));
    }
    Ok(())
}

fn unsupported(instrument: &str, operation: &Operation) -> BackendError {
    malformed(format!(
        "{:?} is unsupported by {instrument}",
        operation.capability()
    ))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use crate::domain::{InstrumentId, TargetId};
    use crate::instruments::{Bpio2Config, NumatoConfig, SerialBinding, SimulatorConfig};
    use crate::supervisor::ArtifactResolver;

    use super::*;

    struct NoArtifacts;

    impl ArtifactResolver for NoArtifacts {
        fn resolve(
            &self,
            digest: &ArtifactDigest,
        ) -> Result<crate::evidence::VerifiedArtifact, crate::evidence::EvidenceError> {
            Err(crate::evidence::EvidenceError::DigestMismatch {
                digest: digest.clone(),
            })
        }
    }

    fn ids() -> (TargetId, InstrumentId) {
        (
            TargetId::try_from("target").unwrap_or_else(|error| panic!("target: {error}")),
            InstrumentId::try_from("instrument")
                .unwrap_or_else(|error| panic!("instrument: {error}")),
        )
    }

    fn bpio_binding() -> DeviceBinding {
        DeviceBinding {
            config: InstrumentConfig::Bpio2(Bpio2Config {
                serial: SerialBinding {
                    path: PathBuf::from("/dev/ttyTEST"),
                    baud_rate: 115_200,
                    expected_usb_identity: "usb:2a19:0001:test".to_owned(),
                },
                spi_hz: 1_000_000,
                i2c_hz: 100_000,
                uart_baud: 115_200,
                psu_max_millivolts: 3_300,
                psu_max_milliamps: 300,
                pin_map: BTreeMap::from([("reset".to_owned(), 1)]),
                flash_capacity_bytes: Some(64 * 1024),
                flash_page_bytes: Some(256),
                flash_erase_bytes: Some(4_096),
                flash_four_byte_addressing: false,
            }),
            target_fingerprint: ArtifactDigest::sha256(b"target"),
            fixture_revision: ArtifactDigest::sha256(b"fixture"),
            flash_identity: Some(super::super::FlashIdentity {
                jedec_id: [1, 2, 3],
                sfdp_digest: ArtifactDigest::sha256(b"sfdp"),
            }),
        }
    }

    #[test]
    fn rejects_unaligned_later_flash_effect_before_artifact_or_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let (target, instrument) = ids();
        let operation = Operation::FlashErase {
            target,
            instrument,
            offset: 1,
            length: 4_096,
        };
        let error = match validate(&bpio_binding(), &operation, &NoArtifacts) {
            Ok(()) => return Err("unaligned erase reached later validation".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not aligned"));
        Ok(())
    }

    #[test]
    fn rejects_gpio_outside_commissioned_fixture_map() -> Result<(), Box<dyn std::error::Error>> {
        let (target, instrument) = ids();
        let operation = Operation::GpioSet {
            target,
            instrument,
            pin: 2,
            high: true,
        };
        let error = match validate(&bpio_binding(), &operation, &NoArtifacts) {
            Ok(()) => return Err("unmapped GPIO reached later validation".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("fixture pin map"));
        Ok(())
    }

    #[test]
    fn rejects_simulator_flash_range_before_later_write() -> Result<(), Box<dyn std::error::Error>>
    {
        let (target, instrument) = ids();
        let binding = DeviceBinding {
            config: InstrumentConfig::Simulator(SimulatorConfig {
                identity: "preflight-simulator".try_into()?,
                flash_bytes: 64,
            }),
            target_fingerprint: ArtifactDigest::sha256(b"target"),
            fixture_revision: ArtifactDigest::sha256(b"fixture"),
            flash_identity: None,
        };
        let operation = Operation::FlashWrite {
            target,
            instrument,
            offset: 63,
            source: ArtifactDigest::sha256(b"candidate"),
            length: 2,
        };
        let error = match validate(&binding, &operation, &NoArtifacts) {
            Ok(()) => return Err("out-of-range simulator write reached artifact resolution".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("range exceeds"));
        Ok(())
    }

    #[test]
    fn rejects_numato_relay_outside_commissioned_map() -> Result<(), Box<dyn std::error::Error>> {
        let (target, instrument) = ids();
        let binding = DeviceBinding {
            config: InstrumentConfig::Numato(NumatoConfig {
                serial: SerialBinding {
                    path: PathBuf::from("/dev/ttyTEST"),
                    baud_rate: 19_200,
                    expected_usb_identity: "usb:2a19:0002:test".to_owned(),
                },
                relay_map: BTreeMap::from([("power".to_owned(), 0)]),
            }),
            target_fingerprint: ArtifactDigest::sha256(b"target"),
            fixture_revision: ArtifactDigest::sha256(b"fixture"),
            flash_identity: None,
        };
        let operation = Operation::RelaySet {
            target,
            instrument,
            relay: 1,
            closed: true,
        };
        let error = match validate(&binding, &operation, &NoArtifacts) {
            Ok(()) => return Err("unmapped Numato relay reached later validation".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Numato fixture map"));
        Ok(())
    }

    #[test]
    fn rejects_i2c_request_that_runtime_cannot_split() -> Result<(), Box<dyn std::error::Error>> {
        let (target, instrument) = ids();
        let operation = Operation::I2cTransfer {
            target,
            instrument,
            address: 0x50,
            tx: vec![0; usize::from(u16::MAX)],
            rx_bytes: 0,
        };
        let error = match validate(&bpio_binding(), &operation, &NoArtifacts) {
            Ok(()) => return Err("oversize I2C request reached later runtime validation".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsplittable BPIO2 u16"));
        Ok(())
    }
}
