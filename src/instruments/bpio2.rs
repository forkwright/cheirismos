//! Bus Pirate BPIO2 transport over an already supervisor-bound serial stream.
//!
//! The adapter uses BPIO2's generated FlatBuffer bindings and COBS framing. A
//! successful status query is discovery only; callers must record separately which
//! protocol operations have been qualified on a commissioned fixture.

use std::time::Duration;

use bpio2::{
    ConfigurationRequestBuilder, DataRequestBuilder, ModeConfigurationBuilder,
    RequestPacketBuilder, RequestPacketContents, ResponsePacketContents, StatusRequestBuilder,
    StatusRequestTypes,
};
use flatbuffers::FlatBufferBuilder;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use tokio_serial::SerialPortBuilderExt;

use super::{InstrumentError, SerialBinding, cobs};

const BPIO2_MAJOR: u8 = 2;
const BPIO2_MINIMUM_MINOR: u16 = 0;
const DISCOVERY_FRAME_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bpio2Discovery {
    pub flatbuffer_major: u8,
    pub flatbuffer_minor: u16,
    pub hardware_major: u8,
    pub hardware_minor: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub firmware_git_hash: Option<String>,
    pub firmware_date: Option<String>,
    pub modes_available: Vec<String>,
    pub mode_current: Option<String>,
    pub max_packet_bytes: u32,
    pub max_write_bytes: u32,
    pub max_read_bytes: u32,
    pub psu_enabled: bool,
    pub psu_set_millivolts: u32,
    pub psu_set_milliamps: u32,
    pub psu_measured_millivolts: u32,
    pub psu_measured_milliamps: u32,
    pub adc_millivolts: Vec<u32>,
    pub io_direction: u8,
    pub io_value: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeConfig {
    pub speed: u32,
    pub clock_polarity: bool,
    pub clock_phase: bool,
    pub chip_select_idle: bool,
    pub clock_stretch: bool,
    pub data_bits: u8,
    pub parity: bool,
    pub stop_bits: u8,
    pub flow_control: bool,
    pub signal_inversion: bool,
}

enum PsuSetting {
    Enable { millivolts: u32, milliamps: u16 },
    Disable,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            speed: 20_000,
            clock_polarity: false,
            clock_phase: false,
            chip_select_idle: true,
            clock_stretch: false,
            data_bits: 8,
            parity: false,
            stop_bits: 1,
            flow_control: false,
            signal_inversion: false,
        }
    }
}

pub struct Bpio2Adapter<T> {
    stream: T,
    timeout: Duration,
    frame_limit: usize,
    discovery: Option<Bpio2Discovery>,
}

impl<T> Bpio2Adapter<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: T, timeout: Duration) -> Self {
        Self {
            stream,
            timeout,
            frame_limit: DISCOVERY_FRAME_LIMIT,
            discovery: None,
        }
    }

    pub fn discovery(&self) -> Option<&Bpio2Discovery> {
        self.discovery.as_ref()
    }

    pub async fn identify(&mut self) -> Result<Bpio2Discovery, InstrumentError> {
        let packet = build_status_request();
        let response_bytes = self.request(&packet).await?;
        let response = bpio2::root_as_response_packet(&response_bytes).map_err(|error| {
            InstrumentError::MalformedResponse {
                detail: error.to_string(),
            }
        })?;
        reject_packet_error(response.error())?;
        if response.contents_type() != ResponsePacketContents::StatusResponse {
            return Err(InstrumentError::UnexpectedResponse {
                expected: "BPIO2 status",
                actual: format!("{:?}", response.contents_type()),
            });
        }
        let status = response.contents_as_status_response().ok_or_else(|| {
            InstrumentError::MalformedResponse {
                detail: "status union has no status payload".to_owned(),
            }
        })?;
        reject_packet_error(status.error())?;
        let modes_available = status
            .modes_available()
            .map(|modes| modes.iter().map(str::to_owned).collect())
            .unwrap_or_default();
        let adc_millivolts = status
            .adc_mv()
            .map(|values| values.iter().collect())
            .unwrap_or_default();
        let discovery = Bpio2Discovery {
            flatbuffer_major: status.version_flatbuffers_major(),
            flatbuffer_minor: status.version_flatbuffers_minor(),
            hardware_major: status.version_hardware_major(),
            hardware_minor: status.version_hardware_minor(),
            firmware_major: status.version_firmware_major(),
            firmware_minor: status.version_firmware_minor(),
            firmware_git_hash: status.version_firmware_git_hash().map(str::to_owned),
            firmware_date: status.version_firmware_date().map(str::to_owned),
            modes_available,
            mode_current: status.mode_current().map(str::to_owned),
            max_packet_bytes: status.mode_max_packet_size(),
            max_write_bytes: status.mode_max_write(),
            max_read_bytes: status.mode_max_read(),
            psu_enabled: status.psu_enabled(),
            psu_set_millivolts: status.psu_set_mv(),
            psu_set_milliamps: status.psu_set_ma(),
            psu_measured_millivolts: status.psu_measured_mv(),
            psu_measured_milliamps: status.psu_measured_ma(),
            adc_millivolts,
            io_direction: status.io_direction(),
            io_value: status.io_value(),
        };
        self.frame_limit = usize::try_from(discovery.max_packet_bytes)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(DISCOVERY_FRAME_LIMIT)
            .min(DISCOVERY_FRAME_LIMIT);
        self.discovery = Some(discovery.clone());
        Ok(discovery)
    }

    pub async fn configure_mode(
        &mut self,
        mode: &str,
        config: ModeConfig,
    ) -> Result<(), InstrumentError> {
        self.require_discovered_mode(mode)?;
        let packet = build_configuration_request(mode, config, None, None, None, None);
        self.expect_configuration_response(&packet).await
    }

    pub async fn set_psu(
        &mut self,
        millivolts: u32,
        milliamps: u16,
    ) -> Result<(), InstrumentError> {
        let setting = if millivolts == 0 && milliamps == 0 {
            PsuSetting::Disable
        } else {
            PsuSetting::Enable {
                millivolts,
                milliamps,
            }
        };
        let packet =
            build_configuration_request("", ModeConfig::default(), Some(setting), None, None, None);
        self.expect_configuration_response(&packet).await
    }

    pub async fn set_gpio(&mut self, pin: u8, high: bool) -> Result<(), InstrumentError> {
        if pin >= 8 {
            return Err(InstrumentError::ProtocolLimit {
                requested: usize::from(pin),
                limit: 7,
            });
        }
        let mask = 1u8 << pin;
        let value = if high { mask } else { 0 };
        let packet = build_configuration_request(
            "",
            ModeConfig::default(),
            None,
            Some((mask, mask)),
            Some((mask, value)),
            None,
        );
        self.expect_configuration_response(&packet).await
    }

    pub async fn transfer(
        &mut self,
        write: &[u8],
        read_bytes: u16,
        start: bool,
        stop: bool,
    ) -> Result<Vec<u8>, InstrumentError> {
        self.transfer_with_length_policy(write, read_bytes, start, stop, true)
            .await
    }

    /// Transfer a bounded UART capture. Unlike SPI/I2C, UART has no transaction
    /// length guarantee: firmware may return fewer currently buffered bytes.
    pub async fn transfer_up_to(
        &mut self,
        write: &[u8],
        read_bytes: u16,
        start: bool,
        stop: bool,
    ) -> Result<Vec<u8>, InstrumentError> {
        self.transfer_with_length_policy(write, read_bytes, start, stop, false)
            .await
    }

    async fn transfer_with_length_policy(
        &mut self,
        write: &[u8],
        read_bytes: u16,
        start: bool,
        stop: bool,
        exact_read_length: bool,
    ) -> Result<Vec<u8>, InstrumentError> {
        if let Some(discovery) = &self.discovery {
            if write.len() > discovery.max_write_bytes as usize {
                return Err(InstrumentError::ProtocolLimit {
                    requested: write.len(),
                    limit: discovery.max_write_bytes as usize,
                });
            }
            if usize::from(read_bytes) > discovery.max_read_bytes as usize {
                return Err(InstrumentError::ProtocolLimit {
                    requested: usize::from(read_bytes),
                    limit: discovery.max_read_bytes as usize,
                });
            }
        }
        let packet = build_data_request(write, read_bytes, start, stop);
        let response_bytes = self.request(&packet).await?;
        let response = bpio2::root_as_response_packet(&response_bytes).map_err(|error| {
            InstrumentError::MalformedResponse {
                detail: error.to_string(),
            }
        })?;
        reject_packet_error(response.error())?;
        if response.contents_type() != ResponsePacketContents::DataResponse {
            return Err(InstrumentError::UnexpectedResponse {
                expected: "BPIO2 data",
                actual: format!("{:?}", response.contents_type()),
            });
        }
        let data = response.contents_as_data_response().ok_or_else(|| {
            InstrumentError::MalformedResponse {
                detail: "data union has no data payload".to_owned(),
            }
        })?;
        reject_packet_error(data.error())?;
        let read: Vec<u8> = data
            .data_read()
            .map(|bytes| bytes.iter().collect())
            .unwrap_or_default();
        if exact_read_length && read.len() != usize::from(read_bytes) {
            return Err(InstrumentError::MalformedResponse {
                detail: format!(
                    "BPIO2 data response has {} bytes, expected {read_bytes}",
                    read.len()
                ),
            });
        }
        Ok(read)
    }

    async fn expect_configuration_response(
        &mut self,
        packet: &[u8],
    ) -> Result<(), InstrumentError> {
        let response_bytes = self.request(packet).await?;
        let response = bpio2::root_as_response_packet(&response_bytes).map_err(|error| {
            InstrumentError::MalformedResponse {
                detail: error.to_string(),
            }
        })?;
        reject_packet_error(response.error())?;
        if response.contents_type() != ResponsePacketContents::ConfigurationResponse {
            return Err(InstrumentError::UnexpectedResponse {
                expected: "BPIO2 configuration",
                actual: format!("{:?}", response.contents_type()),
            });
        }
        let configuration = response
            .contents_as_configuration_response()
            .ok_or_else(|| InstrumentError::MalformedResponse {
                detail: "configuration union has no configuration payload".to_owned(),
            })?;
        reject_packet_error(configuration.error())
    }

    async fn request(&mut self, packet: &[u8]) -> Result<Vec<u8>, InstrumentError> {
        if packet.len() > self.frame_limit {
            return Err(InstrumentError::FrameTooLarge {
                limit: self.frame_limit,
            });
        }
        timeout(self.timeout, async {
            let encoded = cobs::encode(packet);
            self.stream
                .write_all(&encoded)
                .await
                .map_err(|source| InstrumentError::Io {
                    action: "writing BPIO2 frame",
                    source,
                })?;
            self.stream
                .flush()
                .await
                .map_err(|source| InstrumentError::Io {
                    action: "flushing BPIO2 frame",
                    source,
                })?;
            cobs::read_delimited(&mut self.stream, self.frame_limit, "reading BPIO2 frame").await
        })
        .await
        .map_err(|_| InstrumentError::Timeout {
            operation: "reading BPIO2 frame",
        })?
    }

    fn require_discovered_mode(&self, mode: &str) -> Result<(), InstrumentError> {
        let discovery = self
            .discovery
            .as_ref()
            .ok_or_else(|| InstrumentError::DeviceRejected {
                detail: "BPIO2 mode configuration requires a fresh status observation".to_owned(),
            })?;
        if mode.is_empty()
            || discovery
                .modes_available
                .iter()
                .any(|available| available.eq_ignore_ascii_case(mode))
        {
            Ok(())
        } else {
            Err(InstrumentError::DeviceRejected {
                detail: format!("firmware did not report {mode} mode"),
            })
        }
    }
}

impl Bpio2Adapter<tokio_serial::SerialStream> {
    /// Opens the supervisor-selected port. Agent/API input never reaches this boundary.
    pub fn open_bound(serial: &SerialBinding, timeout: Duration) -> Result<Self, InstrumentError> {
        let stream = tokio_serial::new(serial.path.to_string_lossy(), serial.baud_rate)
            .open_native_async()
            .map_err(|source| InstrumentError::Io {
                action: "opening supervisor-bound Bus Pirate port",
                source: source.into(),
            })?;
        Ok(Self::new(stream, timeout))
    }
}

fn reject_packet_error(error: Option<&str>) -> Result<(), InstrumentError> {
    if let Some(detail) = error.filter(|detail| !detail.is_empty()) {
        return Err(InstrumentError::DeviceRejected {
            detail: detail.to_owned(),
        });
    }
    Ok(())
}

fn build_status_request() -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let query = builder.create_vector(&[StatusRequestTypes::All]);
    let mut status = StatusRequestBuilder::new(&mut builder);
    status.add_query(query);
    let status = status.finish();
    finish_request(
        &mut builder,
        RequestPacketContents::StatusRequest,
        status.as_union_value(),
    )
}

fn build_configuration_request(
    mode: &str,
    config: ModeConfig,
    psu: Option<PsuSetting>,
    direction: Option<(u8, u8)>,
    value: Option<(u8, u8)>,
    pullup: Option<bool>,
) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let mode_name = (!mode.is_empty()).then(|| builder.create_string(mode));
    let mut mode_config = ModeConfigurationBuilder::new(&mut builder);
    mode_config.add_speed(config.speed);
    mode_config.add_data_bits(config.data_bits);
    mode_config.add_parity(config.parity);
    mode_config.add_stop_bits(config.stop_bits);
    mode_config.add_flow_control(config.flow_control);
    mode_config.add_signal_inversion(config.signal_inversion);
    mode_config.add_clock_stretch(config.clock_stretch);
    mode_config.add_clock_polarity(config.clock_polarity);
    mode_config.add_clock_phase(config.clock_phase);
    mode_config.add_chip_select_idle(config.chip_select_idle);
    let mode_config = mode_config.finish();
    let mut request = ConfigurationRequestBuilder::new(&mut builder);
    if let Some(mode_name) = mode_name {
        request.add_mode(mode_name);
        request.add_mode_configuration(mode_config);
    }
    if let Some(psu) = psu {
        match psu {
            PsuSetting::Enable {
                millivolts,
                milliamps,
            } => {
                request.add_psu_enable(true);
                request.add_psu_set_mv(millivolts);
                request.add_psu_set_ma(milliamps);
            }
            PsuSetting::Disable => request.add_psu_disable(true),
        }
    }
    if let Some(enabled) = pullup {
        if enabled {
            request.add_pullup_enable(true);
        } else {
            request.add_pullup_disable(true);
        }
    }
    if let Some((mask, directions)) = direction {
        request.add_io_direction_mask(mask);
        request.add_io_direction(directions);
    }
    if let Some((mask, values)) = value {
        request.add_io_value_mask(mask);
        request.add_io_value(values);
    }
    let request = request.finish();
    finish_request(
        &mut builder,
        RequestPacketContents::ConfigurationRequest,
        request.as_union_value(),
    )
}

fn build_data_request(write: &[u8], read_bytes: u16, start: bool, stop: bool) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let write = builder.create_vector(write);
    let mut request = DataRequestBuilder::new(&mut builder);
    request.add_start_main(start);
    request.add_data_write(write);
    request.add_bytes_read(read_bytes);
    request.add_stop_main(stop);
    let request = request.finish();
    finish_request(
        &mut builder,
        RequestPacketContents::DataRequest,
        request.as_union_value(),
    )
}

fn finish_request(
    builder: &mut FlatBufferBuilder<'_>,
    contents_type: RequestPacketContents,
    contents: flatbuffers::WIPOffset<flatbuffers::UnionWIPOffset>,
) -> Vec<u8> {
    let mut request = RequestPacketBuilder::new(builder);
    request.add_version_major(BPIO2_MAJOR);
    request.add_minimum_version_minor(BPIO2_MINIMUM_MINOR);
    request.add_contents_type(contents_type);
    request.add_contents(contents);
    let request = request.finish();
    builder.finish_minimal(request);
    builder.finished_data().to_vec()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bpio2::{DataResponseBuilder, ResponsePacketBuilder, ResponsePacketContents};
    use flatbuffers::FlatBufferBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{Bpio2Adapter, cobs};
    use crate::instruments::InstrumentError;

    #[tokio::test]
    async fn rejects_malformed_partial_response_frames() {
        let (client, mut peer) = tokio::io::duplex(128);
        let responder = tokio::spawn(async move {
            let mut request = [0u8; 128];
            let _ = peer.read(&mut request).await;
            peer.write_all(&[3, 0xAA, 0])
                .await
                .unwrap_or_else(|error| panic!("write malformed frame: {error}"));
        });
        let mut adapter = Bpio2Adapter::new(client, Duration::from_secs(1));
        let result = adapter.identify().await;
        responder
            .await
            .unwrap_or_else(|error| panic!("responder: {error}"));
        assert!(matches!(result, Err(InstrumentError::MalformedCobs)));
    }

    #[test]
    fn writes_are_cobs_framed() {
        let packet = super::build_data_request(&[0, 1, 2], 0, false, false);
        let frame = cobs::encode(&packet);
        assert_eq!(frame.last(), Some(&0));
        assert_eq!(
            cobs::decode(&frame[..frame.len() - 1], 4096).unwrap_or_default(),
            packet
        );
    }

    #[test]
    fn zero_psu_request_uses_firmware_disable_flag() {
        let packet = super::build_configuration_request(
            "",
            super::ModeConfig::default(),
            Some(super::PsuSetting::Disable),
            None,
            None,
            None,
        );
        let request = flatbuffers::root::<bpio2::RequestPacket<'_>>(&packet)
            .unwrap_or_else(|error| panic!("configuration request: {error}"));
        let configuration = request
            .contents_as_configuration_request()
            .unwrap_or_else(|| panic!("configuration payload"));
        assert!(configuration.psu_disable());
        assert!(!configuration.psu_enable());
    }

    #[tokio::test]
    async fn duplex_transcript_preserves_combined_i2c_data_request() {
        let (client, mut peer) = tokio::io::duplex(256);
        let responder = tokio::spawn(async move {
            let frame = cobs::read_delimited(&mut peer, 4096, "read request")
                .await
                .unwrap_or_else(|error| panic!("request frame: {error}"));
            let request = flatbuffers::root::<bpio2::RequestPacket<'_>>(&frame)
                .unwrap_or_else(|error| panic!("request packet: {error}"));
            let data = request
                .contents_as_data_request()
                .unwrap_or_else(|| panic!("data request payload"));
            assert!(data.start_main());
            assert!(data.stop_main());
            assert_eq!(data.bytes_read(), 2);
            assert_eq!(
                data.data_write()
                    .map(|bytes| bytes.iter().collect::<Vec<_>>()),
                Some(vec![0xA4, 0x00])
            );
            peer.write_all(&cobs::encode(&data_response(&[0x11, 0x22])))
                .await
                .unwrap_or_else(|error| panic!("write response: {error}"));
        });
        let mut adapter = Bpio2Adapter::new(client, Duration::from_secs(1));
        let response = adapter
            .transfer(&[0xA4, 0x00], 2, true, true)
            .await
            .unwrap_or_else(|error| panic!("combined transfer: {error}"));
        responder
            .await
            .unwrap_or_else(|error| panic!("responder: {error}"));
        assert_eq!(response, [0x11, 0x22]);
    }

    #[tokio::test]
    async fn rejects_short_data_response() {
        let (client, mut peer) = tokio::io::duplex(256);
        let responder = tokio::spawn(async move {
            let mut request = [0u8; 256];
            let _ = peer.read(&mut request).await;
            let response = data_response(&[0xA5]);
            peer.write_all(&cobs::encode(&response))
                .await
                .unwrap_or_else(|error| panic!("write response: {error}"));
        });
        let mut adapter = Bpio2Adapter::new(client, Duration::from_secs(1));
        let result = adapter.transfer(&[], 2, false, false).await;
        responder
            .await
            .unwrap_or_else(|error| panic!("responder: {error}"));
        assert!(matches!(
            result,
            Err(InstrumentError::MalformedResponse { .. })
        ));
    }

    fn data_response(read: &[u8]) -> Vec<u8> {
        let mut builder = FlatBufferBuilder::new();
        let read = builder.create_vector(read);
        let mut data = DataResponseBuilder::new(&mut builder);
        data.add_data_read(read);
        let data = data.finish();
        let mut response = ResponsePacketBuilder::new(&mut builder);
        response.add_contents_type(ResponsePacketContents::DataResponse);
        response.add_contents(data.as_union_value());
        let response = response.finish();
        builder.finish_minimal(response);
        builder.finished_data().to_vec()
    }
}
