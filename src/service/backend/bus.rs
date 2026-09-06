//! Bus Pirate operations over the already-bound BPIO2 transport.
//!
//! This module never selects a device path or accepts a shell command. It starts
//! from a fresh status observation, constrains every transfer to firmware limits,
//! and returns raw bytes for the enclosing backend to publish as evidence.

use std::cmp::min;

use serde_json::{Value, json};
use tokio::time::{Duration, sleep};
use tokio_serial::SerialStream;

use crate::domain::{ArtifactDigest, Operation};
use crate::instruments::{
    AddressMode, Bpio2Adapter, Bpio2Discovery, FlashGeometry, InstrumentConfig, InstrumentError,
    ModeConfig,
};
use crate::supervisor::{ArtifactResolver, BackendError};

use super::{DeviceBinding, ResultData, malformed, source_bytes, transport};

const SPI_MODE: &str = "SPI";
const I2C_MODE: &str = "I2C";
const UART_MODE: &str = "UART";
const BUSY_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Execute a BPIO2 operation. The outer backend owns the operation deadline.
pub(super) async fn execute(
    adapter: &mut Bpio2Adapter<SerialStream>,
    binding: &DeviceBinding,
    operation: &Operation,
    artifacts: &dyn ArtifactResolver,
    reconcile: bool,
    configure_instrument: bool,
) -> Result<ResultData, BackendError> {
    let fresh = adapter.identify().await.map_err(transport)?;
    let base = status_body(&fresh, reconcile);
    match operation {
        Operation::InstrumentStatus { .. } => Ok(ResultData::observation(base)),
        Operation::SpiTransfer { tx, rx_bytes, .. } => {
            if reconcile {
                return Ok(unknown_raw(
                    base,
                    "raw SPI transfer cannot prove its original effect",
                ));
            }
            require_configuration_effect(configure_instrument)?;
            let limits = ensure_mode(adapter, &fresh, SPI_MODE, spi_speed(binding)).await?;
            let bytes = spi_transfer(adapter, tx, *rx_bytes, &limits).await?;
            Ok(with_bytes(configuration_applied(base), bytes, "spi"))
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
            if reconcile {
                return Ok(unknown_raw(
                    base,
                    "raw I2C transfer cannot prove its original effect",
                ));
            }
            require_configuration_effect(configure_instrument)?;
            let limits = ensure_mode(adapter, &fresh, I2C_MODE, i2c_speed(binding)).await?;
            let bytes = i2c_transfer(adapter, *address, tx, *rx_bytes, &limits).await?;
            Ok(with_bytes(configuration_applied(base), bytes, "i2c"))
        }
        Operation::I2cScan { .. } => {
            if reconcile {
                return Ok(unknown_raw(
                    base,
                    "I2C scan cannot prove its original probe effects",
                ));
            }
            require_configuration_effect(configure_instrument)?;
            let limits = ensure_mode(adapter, &fresh, I2C_MODE, i2c_speed(binding)).await?;
            let addresses = i2c_scan(adapter, &limits).await?;
            Ok(ResultData::observation(merge(
                configuration_applied(base),
                json!({"i2c_acknowledged_addresses":addresses}),
            )))
        }
        Operation::UartCapture { max_bytes, .. } => {
            if !reconcile {
                require_configuration_effect(configure_instrument)?;
            }
            let limits = if configure_instrument {
                Some(ensure_mode(adapter, &fresh, UART_MODE, uart_speed(binding)).await?)
            } else {
                None
            };
            let limits = match limits {
                Some(limits) => limits,
                None => return Ok(mode_unavailable(base, UART_MODE)),
            };
            if !reconcile {
                let bytes = uart_capture(adapter, *max_bytes, &limits).await?;
                return Ok(uart_result(
                    configuration_applied(base),
                    bytes,
                    *max_bytes,
                    "uart",
                ));
            }
            let bytes = uart_capture(adapter, *max_bytes, &limits).await?;
            Ok(uart_result(
                configuration_applied(base),
                bytes,
                *max_bytes,
                "uart_reconciliation",
            ))
        }
        Operation::UartTransmit { bytes, .. } => {
            if reconcile {
                return Ok(unknown_raw(
                    base,
                    "UART transmit cannot prove its original effect",
                ));
            }
            require_configuration_effect(configure_instrument)?;
            let limits = ensure_mode(adapter, &fresh, UART_MODE, uart_speed(binding)).await?;
            uart_transmit(adapter, bytes, &limits).await?;
            Ok(ResultData::observation(merge(
                configuration_applied(base),
                json!({"uart_transmitted_bytes":bytes.len()}),
            )))
        }
        Operation::GpioSet { pin, high, .. } => {
            let pin = u8::try_from(*pin).map_err(malformed)?;
            if pin >= 8 {
                return Err(malformed("GPIO pin is outside Bus Pirate pin range"));
            }
            if !bpio_config(binding)?
                .pin_map
                .values()
                .any(|configured| *configured == pin)
            {
                return Err(malformed(
                    "GPIO pin is outside the configured fixture pin map",
                ));
            }
            if !reconcile {
                adapter.set_gpio(pin, *high).await.map_err(transport)?;
            }
            let observed = adapter.identify().await.map_err(transport)?;
            let actual = observed.io_value & (1u8 << pin) != 0;
            let mut result = ResultData::observation(merge(
                status_body(&observed, reconcile),
                json!({
                    "gpio_pin":pin,"requested_high":high,"observed_high":actual,
                }),
            ));
            if actual != *high {
                result.partial = Some("GPIO status differs from requested state".to_owned());
            }
            Ok(result)
        }
        Operation::AdcRead { channel, .. } => {
            let channel = usize::from(*channel);
            let millivolts = fresh.adc_millivolts.get(channel).copied().ok_or_else(|| {
                malformed("ADC channel is not reported by the connected Bus Pirate")
            })?;
            Ok(ResultData::observation(merge(
                base,
                json!({"adc_channel":channel,"millivolts":millivolts}),
            )))
        }
        Operation::PsuSet {
            millivolts,
            milliamps,
            ..
        } => {
            let config = bpio_config(binding)?;
            if *millivolts > config.psu_max_millivolts || *milliamps > config.psu_max_milliamps {
                return Err(malformed(
                    "PSU request exceeds configured electrical limits",
                ));
            }
            let milliamps = u16::try_from(*milliamps).map_err(malformed)?;
            if !reconcile {
                adapter
                    .set_psu(*millivolts, milliamps)
                    .await
                    .map_err(transport)?;
            }
            let observed = adapter.identify().await.map_err(transport)?;
            let expected_enabled = *millivolts != 0 || milliamps != 0;
            let matches = observed.psu_enabled == expected_enabled
                && (!expected_enabled
                    || (observed.psu_set_millivolts == *millivolts
                        && observed.psu_set_milliamps == u32::from(milliamps)));
            let mut result = ResultData::observation(merge(
                status_body(&observed, reconcile),
                json!({
                    "psu_requested_millivolts":millivolts,"psu_requested_milliamps":milliamps,
                    "psu_matches_request":matches,
                }),
            ));
            if !matches {
                result.partial = Some("PSU status differs from requested state".to_owned());
            }
            Ok(result)
        }
        Operation::FlashIdentify { .. } => {
            if !reconcile {
                require_configuration_effect(configure_instrument)?;
            }
            let limits = flash_limits(adapter, &fresh, binding, configure_instrument).await?;
            let limits = match limits {
                Some(limits) => limits,
                None => return Ok(mode_unavailable(base, SPI_MODE)),
            };
            let (jedec, sfdp) = identify_flash(adapter, &limits).await?;
            let mut bytes = jedec.to_vec();
            bytes.extend_from_slice(&sfdp);
            Ok(ResultData::bytes(
                bytes,
                merge(
                    configuration_applied(base),
                    json!({
                        "jedec_id":jedec,"sfdp_digest":ArtifactDigest::sha256(&sfdp),
                    }),
                ),
            ))
        }
        Operation::FlashRead { offset, length, .. } => {
            let geometry = qualified_flash_geometry(binding)?;
            if !reconcile {
                require_configuration_effect(configure_instrument)?;
            }
            let limits = flash_limits(adapter, &fresh, binding, configure_instrument).await?;
            let limits = match limits {
                Some(limits) => limits,
                None => return Ok(mode_unavailable(base, SPI_MODE)),
            };
            verify_flash_identity(adapter, binding, &limits).await?;
            let bytes = flash_read(adapter, &geometry, *offset, *length, &limits).await?;
            Ok(with_bytes(
                merge(
                    configuration_applied(base),
                    json!({"flash_offset":offset,"flash_length":length}),
                ),
                bytes,
                "flash_read",
            ))
        }
        Operation::FlashErase { offset, length, .. } => {
            let geometry = qualified_flash_geometry(binding)?;
            if !reconcile {
                require_configuration_effect(configure_instrument)?;
            }
            let limits = flash_limits(adapter, &fresh, binding, configure_instrument).await?;
            let limits = match limits {
                Some(limits) => limits,
                None => return Ok(mode_unavailable(base, SPI_MODE)),
            };
            verify_flash_identity(adapter, binding, &limits).await?;
            if !reconcile {
                flash_erase(adapter, &geometry, *offset, *length, &limits).await?;
            }
            let actual = flash_read(adapter, &geometry, *offset, *length, &limits).await?;
            let blank = actual.iter().all(|byte| *byte == 0xff);
            let mut result = with_bytes(
                merge(
                    configuration_applied(base),
                    json!({
                        "flash_offset":offset,"flash_length":length,"all_erased":blank,
                        "readback_digest":ArtifactDigest::sha256(&actual),
                    }),
                ),
                actual,
                "flash_erase_readback",
            );
            if !blank {
                result.partial = Some("flash erase readback is not fully erased".to_owned());
            }
            Ok(result)
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
            let geometry = qualified_flash_geometry(binding)?;
            let candidate = source_bytes(artifacts, source, *length)?;
            if !reconcile {
                require_configuration_effect(configure_instrument)?;
            }
            let limits = flash_limits(adapter, &fresh, binding, configure_instrument).await?;
            let limits = match limits {
                Some(limits) => limits,
                None => return Ok(mode_unavailable(base, SPI_MODE)),
            };
            verify_flash_identity(adapter, binding, &limits).await?;
            if matches!(operation, Operation::FlashWrite { .. }) && !reconcile {
                flash_write(adapter, &geometry, *offset, &candidate, &limits).await?;
            }
            let actual = flash_read(adapter, &geometry, *offset, *length, &limits).await?;
            let matches = actual == candidate;
            let mut result = with_bytes(
                merge(
                    configuration_applied(base),
                    json!({
                        "flash_offset":offset,"candidate":source,"matches_candidate":matches,
                        "readback_digest":ArtifactDigest::sha256(&actual),
                    }),
                ),
                actual,
                "flash_verify_readback",
            );
            if !matches {
                result.partial =
                    Some("flash readback differs from verified candidate artifact".to_owned());
            }
            Ok(result)
        }
        _ => Err(malformed("operation is unsupported by Bus Pirate BPIO2")),
    }
}

fn bpio_config(binding: &DeviceBinding) -> Result<&crate::instruments::Bpio2Config, BackendError> {
    let InstrumentConfig::Bpio2(config) = &binding.config else {
        return Err(malformed("Bus Pirate adapter configuration mismatch"));
    };
    Ok(config)
}

fn spi_speed(binding: &DeviceBinding) -> u32 {
    bpio_config(binding).map_or(0, |config| config.spi_hz)
}
fn i2c_speed(binding: &DeviceBinding) -> u32 {
    bpio_config(binding).map_or(0, |config| config.i2c_hz)
}
fn uart_speed(binding: &DeviceBinding) -> u32 {
    bpio_config(binding).map_or(0, |config| config.uart_baud)
}

fn status_body(discovery: &Bpio2Discovery, reconcile: bool) -> Value {
    json!({
        "mode":discovery.mode_current,"max_write_bytes":discovery.max_write_bytes,
        "max_read_bytes":discovery.max_read_bytes,"psu_enabled":discovery.psu_enabled,
        "psu_set_millivolts":discovery.psu_set_millivolts,"psu_set_milliamps":discovery.psu_set_milliamps,
        "adc_millivolts":discovery.adc_millivolts,"gpio_value":discovery.io_value,
        "reconciliation":reconcile,"proves_original_actuation":false,
        "instrument_configuration_applied":false,
    })
}

fn merge(mut base: Value, additions: Value) -> Value {
    if let (Value::Object(base_object), Value::Object(additions)) = (&mut base, additions) {
        base_object.extend(additions);
    }
    base
}

fn with_bytes(mut body: Value, bytes: Vec<u8>, field: &str) -> ResultData {
    if let Some(object) = body.as_object_mut() {
        object.insert("capture_kind".to_owned(), json!(field));
        object.insert("capture_bytes".to_owned(), json!(bytes.len()));
        object.insert(
            "capture_digest".to_owned(),
            json!(ArtifactDigest::sha256(&bytes)),
        );
    }
    ResultData::bytes(bytes, body)
}

fn configuration_applied(mut body: Value) -> Value {
    if let Some(object) = body.as_object_mut() {
        object.insert("instrument_configuration_applied".to_owned(), json!(true));
    }
    body
}

fn require_configuration_effect(configure_instrument: bool) -> Result<(), BackendError> {
    if configure_instrument {
        Ok(())
    } else {
        Err(malformed(
            "normal bus operation requires reviewed InstrumentConfigure authority",
        ))
    }
}

fn uart_result(body: Value, bytes: Vec<u8>, requested: u32, field: &str) -> ResultData {
    let observed = bytes.len();
    let mut result = with_bytes(body, bytes, field);
    if (observed as u64) < u64::from(requested) {
        result.partial = Some(format!(
            "UART capture returned {observed} bytes before the requested upper bound {requested}"
        ));
    }
    result
}

fn unknown_raw(base: Value, reason: &str) -> ResultData {
    ResultData {
        body: base,
        bytes: None,
        partial: Some(reason.to_owned()),
    }
}

fn mode_unavailable(base: Value, mode: &str) -> ResultData {
    ResultData {
        body: merge(base, json!({"required_mode":mode})),
        bytes: None,
        partial: Some(
            "instrument configuration was not applied; status cannot prove required bus settings"
                .to_owned(),
        ),
    }
}

async fn ensure_mode(
    adapter: &mut Bpio2Adapter<SerialStream>,
    _discovery: &Bpio2Discovery,
    mode: &str,
    speed: u32,
) -> Result<Limits, BackendError> {
    if speed == 0 {
        return Err(malformed("configured bus speed must be non-zero"));
    }
    // BPIO2 status exposes a mode name and transfer limits, but no active mode
    // configuration. A matching mode name therefore cannot prove configured
    // speed/polarity/UART settings. Normal execution always applies the
    // supervisor's fixed configuration and observes the accepted result again.
    let config = ModeConfig {
        speed,
        ..ModeConfig::default()
    };
    adapter
        .configure_mode(mode, config)
        .await
        .map_err(transport)?;
    let refreshed = adapter.identify().await.map_err(transport)?;
    if !mode_current(&refreshed, mode) {
        return Err(malformed("Bus Pirate did not enter requested mode"));
    }
    Limits::from_discovery(&refreshed)
}

async fn flash_limits(
    adapter: &mut Bpio2Adapter<SerialStream>,
    discovery: &Bpio2Discovery,
    binding: &DeviceBinding,
    configure_instrument: bool,
) -> Result<Option<Limits>, BackendError> {
    if !configure_instrument {
        return Ok(None);
    }
    Ok(Some(
        ensure_mode(adapter, discovery, SPI_MODE, spi_speed(binding)).await?,
    ))
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    write: usize,
    read: usize,
}

impl Limits {
    fn from_discovery(discovery: &Bpio2Discovery) -> Result<Self, BackendError> {
        let write = usize::try_from(discovery.max_write_bytes)
            .map_err(malformed)?
            .min(usize::from(u16::MAX));
        let read = usize::try_from(discovery.max_read_bytes)
            .map_err(malformed)?
            .min(usize::from(u16::MAX));
        if write == 0 || read == 0 {
            return Err(malformed("Bus Pirate reported a zero transfer limit"));
        }
        Ok(Self { write, read })
    }
}

fn mode_current(discovery: &Bpio2Discovery, expected: &str) -> bool {
    discovery
        .mode_current
        .as_deref()
        .is_some_and(|mode| mode.eq_ignore_ascii_case(expected))
}

async fn spi_transfer(
    adapter: &mut Bpio2Adapter<SerialStream>,
    tx: &[u8],
    rx_bytes: u32,
    limits: &Limits,
) -> Result<Vec<u8>, BackendError> {
    bounded_capture(rx_bytes)?;
    let mut started = false;
    for chunk in tx.chunks(limits.write) {
        adapter
            .transfer(chunk, 0, !started, false)
            .await
            .map_err(transport)?;
        started = true;
    }
    let mut received = Vec::new();
    let mut remaining = usize::try_from(rx_bytes).map_err(malformed)?;
    while remaining > 0 {
        let count = min(remaining, limits.read);
        let stop = count == remaining;
        received.extend(
            adapter
                .transfer(
                    &[],
                    u16::try_from(count).map_err(malformed)?,
                    !started,
                    stop,
                )
                .await
                .map_err(transport)?,
        );
        started = true;
        remaining -= count;
    }
    if rx_bytes == 0 && started {
        adapter
            .transfer(&[], 0, false, true)
            .await
            .map_err(transport)?;
    }
    Ok(received)
}

async fn i2c_transfer(
    adapter: &mut Bpio2Adapter<SerialStream>,
    address: u8,
    tx: &[u8],
    rx_bytes: u32,
    limits: &Limits,
) -> Result<Vec<u8>, BackendError> {
    bounded_capture(rx_bytes)?;
    let write_len = tx
        .len()
        .checked_add(1)
        .ok_or_else(|| malformed("I2C write length overflow"))?;
    if write_len > limits.write || usize::try_from(rx_bytes).map_err(malformed)? > limits.read {
        return Err(malformed(
            "I2C transaction exceeds one BPIO2 request; splitting would change restart semantics",
        ));
    }
    // Pinned upstream `BPIOI2C.transfer` sends start_main, data_write, bytes_read,
    // and stop_main in one request. Firmware owns the I2C direction/restart path.
    let mut data_write = Vec::with_capacity(write_len);
    data_write.push(i2c_write_address(address));
    data_write.extend_from_slice(tx);
    adapter
        .transfer(
            &data_write,
            u16::try_from(rx_bytes).map_err(malformed)?,
            true,
            true,
        )
        .await
        .map_err(transport)
}

async fn i2c_scan(
    adapter: &mut Bpio2Adapter<SerialStream>,
    limits: &Limits,
) -> Result<Vec<u8>, BackendError> {
    if limits.write < 1 {
        return Err(malformed("Bus Pirate cannot send I2C address byte"));
    }
    let mut found = Vec::new();
    for address in 0x08u8..=0x77 {
        let write = adapter
            .transfer(&[i2c_write_address(address)], 0, true, true)
            .await;
        let read = adapter
            .transfer(&[i2c_read_address(address)], 1, true, true)
            .await;
        match (write, read) {
            (Ok(_), _) | (_, Ok(_)) => found.push(address),
            (
                Err(InstrumentError::DeviceRejected { detail: write }),
                Err(InstrumentError::DeviceRejected { detail: read }),
            ) if is_i2c_nack(&write) && is_i2c_nack(&read) => {}
            (Err(error), _) if !matches!(error, InstrumentError::DeviceRejected { .. }) => {
                return Err(transport(error));
            }
            (_, Err(error)) if !matches!(error, InstrumentError::DeviceRejected { .. }) => {
                return Err(transport(error));
            }
            (Err(error), Err(_)) => return Err(transport(error)),
        }
    }
    Ok(found)
}

fn is_i2c_nack(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("nack") || detail.contains("not acknowledged")
}

async fn uart_capture(
    adapter: &mut Bpio2Adapter<SerialStream>,
    max_bytes: u32,
    limits: &Limits,
) -> Result<Vec<u8>, BackendError> {
    bounded_capture(max_bytes)?;
    let mut remaining = usize::try_from(max_bytes).map_err(malformed)?;
    let mut bytes = Vec::new();
    while remaining > 0 {
        let requested = min(remaining, limits.read);
        let received = adapter
            .transfer_up_to(
                &[],
                u16::try_from(requested).map_err(malformed)?,
                false,
                false,
            )
            .await
            .map_err(transport)?;
        let short = received.len() < requested;
        bytes.extend(received);
        if short {
            break;
        }
        remaining -= requested;
    }
    Ok(bytes)
}

async fn uart_transmit(
    adapter: &mut Bpio2Adapter<SerialStream>,
    bytes: &[u8],
    limits: &Limits,
) -> Result<(), BackendError> {
    for chunk in bytes.chunks(limits.write) {
        adapter
            .transfer(chunk, 0, false, false)
            .await
            .map_err(transport)?;
    }
    Ok(())
}

fn bounded_capture(length: u32) -> Result<(), BackendError> {
    if usize::try_from(length).map_err(malformed)? > super::MAX_EVIDENCE_BYTES {
        return Err(malformed("requested capture exceeds evidence size limit"));
    }
    Ok(())
}

fn i2c_write_address(address: u8) -> u8 {
    address << 1
}
fn i2c_read_address(address: u8) -> u8 {
    address << 1 | 1
}

struct FlashProfile {
    geometry: FlashGeometry,
    mode: AddressMode,
    page_bytes: u32,
    erase_bytes: u32,
}

fn qualified_flash_geometry(binding: &DeviceBinding) -> Result<FlashProfile, BackendError> {
    let config = bpio_config(binding)?;
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
    Ok(FlashProfile {
        geometry: FlashGeometry::try_new(capacity, page, erase, mode).map_err(malformed)?,
        mode,
        page_bytes: page,
        erase_bytes: erase,
    })
}

async fn identify_flash(
    adapter: &mut Bpio2Adapter<SerialStream>,
    limits: &Limits,
) -> Result<([u8; 3], Vec<u8>), BackendError> {
    let jedec = spi_transfer(adapter, &[0x9f], 3, limits).await?;
    let jedec: [u8; 3] = jedec
        .try_into()
        .map_err(|_| malformed("JEDEC response must be exactly three bytes"))?;
    if limits.write < 5 {
        return Err(malformed(
            "Bus Pirate SPI write limit cannot carry SFDP command",
        ));
    }
    let sfdp = spi_transfer(adapter, &[0x5a, 0, 0, 0, 0], 256, limits).await?;
    Ok((jedec, sfdp))
}

async fn verify_flash_identity(
    adapter: &mut Bpio2Adapter<SerialStream>,
    binding: &DeviceBinding,
    limits: &Limits,
) -> Result<(), BackendError> {
    let expected = binding.flash_identity.as_ref().ok_or_else(|| {
        malformed("flash operation requires commissioned JEDEC and SFDP identity")
    })?;
    let (jedec, sfdp) = identify_flash(adapter, limits).await?;
    if jedec != expected.jedec_id || ArtifactDigest::sha256(&sfdp) != expected.sfdp_digest {
        return Err(malformed(
            "connected flash JEDEC/SFDP identity differs from commissioned binding",
        ));
    }
    Ok(())
}

fn address(mode: AddressMode, offset: u64) -> Vec<u8> {
    match mode {
        AddressMode::ThreeByte => vec![(offset >> 16) as u8, (offset >> 8) as u8, offset as u8],
        AddressMode::FourByte => vec![
            (offset >> 24) as u8,
            (offset >> 16) as u8,
            (offset >> 8) as u8,
            offset as u8,
        ],
    }
}

fn opcodes(mode: AddressMode) -> (u8, u8, u8) {
    match mode {
        AddressMode::ThreeByte => (0x03, 0x02, 0x20),
        AddressMode::FourByte => (0x13, 0x12, 0x21),
    }
}

async fn flash_read(
    adapter: &mut Bpio2Adapter<SerialStream>,
    profile: &FlashProfile,
    offset: u64,
    length: u32,
    limits: &Limits,
) -> Result<Vec<u8>, BackendError> {
    bounded_capture(length)?;
    profile
        .geometry
        .validate_range(offset, length)
        .map_err(malformed)?;
    let (read_opcode, _, _) = opcodes(profile.mode);
    let address_bytes = if matches!(profile.mode, AddressMode::ThreeByte) {
        3
    } else {
        4
    };
    if limits.write < address_bytes + 1 {
        return Err(malformed(
            "Bus Pirate SPI write limit cannot carry flash read command",
        ));
    }
    let mut remaining = usize::try_from(length).map_err(malformed)?;
    let mut cursor = offset;
    let mut bytes = Vec::with_capacity(remaining);
    while remaining > 0 {
        let count = min(remaining, limits.read);
        let mut command = vec![read_opcode];
        command.extend(address(profile.mode, cursor));
        bytes.extend(
            adapter
                .transfer(
                    &command,
                    u16::try_from(count).map_err(malformed)?,
                    true,
                    true,
                )
                .await
                .map_err(transport)?,
        );
        cursor = cursor
            .checked_add(u64::try_from(count).map_err(malformed)?)
            .ok_or_else(|| malformed("flash read offset overflow"))?;
        remaining -= count;
    }
    Ok(bytes)
}

async fn write_enable(adapter: &mut Bpio2Adapter<SerialStream>) -> Result<(), BackendError> {
    adapter
        .transfer(&[0x06], 0, true, true)
        .await
        .map_err(transport)?;
    let status = adapter
        .transfer(&[0x05], 1, true, true)
        .await
        .map_err(transport)?;
    if status.first().is_none_or(|status| status & 0x02 == 0) {
        return Err(malformed("flash did not assert WEL after WREN"));
    }
    Ok(())
}

async fn wait_busy_clear(adapter: &mut Bpio2Adapter<SerialStream>) -> Result<(), BackendError> {
    loop {
        let status = adapter
            .transfer(&[0x05], 1, true, true)
            .await
            .map_err(transport)?;
        if status.first().is_some_and(|status| status & 0x01 == 0) {
            return Ok(());
        }
        sleep(BUSY_POLL_INTERVAL).await;
    }
}

async fn flash_erase(
    adapter: &mut Bpio2Adapter<SerialStream>,
    profile: &FlashProfile,
    offset: u64,
    length: u32,
    limits: &Limits,
) -> Result<(), BackendError> {
    profile
        .geometry
        .validate_erase(offset, length)
        .map_err(malformed)?;
    let (_, _, erase_opcode) = opcodes(profile.mode);
    let sector = u64::from(profile.erase_bytes);
    if limits.write < 1 + address(profile.mode, offset).len() {
        return Err(malformed(
            "Bus Pirate SPI write limit cannot carry flash erase command",
        ));
    }
    for relative in (0..u64::from(length)).step_by(usize::try_from(sector).map_err(malformed)?) {
        write_enable(adapter).await?;
        let absolute = offset
            .checked_add(relative)
            .ok_or_else(|| malformed("flash erase offset overflow"))?;
        let mut command = vec![erase_opcode];
        command.extend(address(profile.mode, absolute));
        adapter
            .transfer(&command, 0, true, true)
            .await
            .map_err(transport)?;
        wait_busy_clear(adapter).await?;
    }
    Ok(())
}

async fn flash_write(
    adapter: &mut Bpio2Adapter<SerialStream>,
    profile: &FlashProfile,
    offset: u64,
    bytes: &[u8],
    limits: &Limits,
) -> Result<(), BackendError> {
    let length = u32::try_from(bytes.len()).map_err(malformed)?;
    profile
        .geometry
        .validate_range(offset, length)
        .map_err(malformed)?;
    let (_, program_opcode, _) = opcodes(profile.mode);
    let overhead = 1 + address(profile.mode, offset).len();
    let max_payload = flash_program_payload_limit(limits, overhead)?;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let absolute = offset
            .checked_add(u64::try_from(cursor).map_err(malformed)?)
            .ok_or_else(|| malformed("flash program offset overflow"))?;
        let page_remaining = usize::try_from(
            u64::from(profile.page_bytes) - absolute % u64::from(profile.page_bytes),
        )
        .map_err(malformed)?;
        let count = min(page_remaining, min(max_payload, bytes.len() - cursor));
        write_enable(adapter).await?;
        let mut command = vec![program_opcode];
        command.extend(address(profile.mode, absolute));
        let page_data = bytes
            .get(cursor..)
            .and_then(|remaining| remaining.get(..count))
            .ok_or_else(|| malformed("flash program page range exceeds verified source bytes"))?;
        command.extend_from_slice(page_data);
        adapter
            .transfer(&command, 0, true, true)
            .await
            .map_err(transport)?;
        wait_busy_clear(adapter).await?;
        cursor += count;
    }
    Ok(())
}

fn flash_program_payload_limit(limits: &Limits, overhead: usize) -> Result<usize, BackendError> {
    let max_payload = limits.write.checked_sub(overhead).ok_or_else(|| {
        malformed("Bus Pirate SPI write limit cannot carry flash program command")
    })?;
    if max_payload == 0 {
        return Err(malformed(
            "Bus Pirate SPI write limit leaves no flash program payload bytes",
        ));
    }
    Ok(max_payload)
}

#[cfg(test)]
mod tests {
    use super::{
        AddressMode, Limits, flash_program_payload_limit, i2c_read_address, i2c_write_address,
        is_i2c_nack, opcodes,
    };

    #[test]
    fn only_documented_i2c_nacks_are_absence() {
        assert!(is_i2c_nack("address NACK"));
        assert!(is_i2c_nack("not acknowledged"));
        assert!(!is_i2c_nack("serial timeout"));
    }

    #[test]
    fn four_byte_flash_uses_dedicated_opcodes() {
        assert_eq!(opcodes(AddressMode::FourByte), (0x13, 0x12, 0x21));
    }

    #[test]
    fn zero_program_payload_rejects_before_write_enable() -> Result<(), Box<dyn std::error::Error>>
    {
        let limits = Limits { write: 4, read: 1 };
        let error = match flash_program_payload_limit(&limits, 4) {
            Ok(_) => return Err("zero program payload was accepted before write enable".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no flash program payload"));
        Ok(())
    }

    #[test]
    fn i2c_uses_seven_bit_address_with_direction_bit() {
        assert_eq!(i2c_write_address(0x52), 0xa4);
        assert_eq!(i2c_read_address(0x52), 0xa5);
    }
}
