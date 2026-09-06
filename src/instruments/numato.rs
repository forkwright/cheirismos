//! Numato four-channel USB-powered DPDT relay adapter.
//!
//! `relay readall` reports the controller's logical coil state. It does not prove
//! the physical contact state, power-loss default, or fixture continuity; those
//! require separately commissioned observations.

use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use tokio_serial::SerialPortBuilderExt;

use super::{InstrumentError, SerialBinding};

const RESPONSE_LIMIT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumatoIdentity {
    pub firmware: String,
    pub module_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    Off,
    On,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayObservation {
    /// Reported by `relay readall`; this is not contact-continuity evidence.
    pub controller_state: [RelayState; 4],
    pub physical_contacts_observed: bool,
}

pub struct NumatoAdapter<T> {
    stream: T,
    timeout: Duration,
}

impl<T> NumatoAdapter<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: T, timeout: Duration) -> Self {
        Self { stream, timeout }
    }

    pub async fn identify(&mut self) -> Result<NumatoIdentity, InstrumentError> {
        let firmware = self.command("ver").await?;
        let module_id = self.command("id get").await?;
        Ok(NumatoIdentity {
            firmware,
            module_id,
        })
    }

    pub async fn set_relay(
        &mut self,
        relay: u8,
        state: RelayState,
    ) -> Result<RelayObservation, InstrumentError> {
        if relay >= 4 {
            return Err(InstrumentError::InvalidRelayResponse {
                response: format!("relay index {relay} outside 0..4"),
            });
        }
        let command = match state {
            RelayState::Off => format!("relay off {relay}"),
            RelayState::On => format!("relay on {relay}"),
        };
        self.command(&command).await?;
        self.read_relays().await
    }

    pub async fn read_relays(&mut self) -> Result<RelayObservation, InstrumentError> {
        let response = self.command("relay readall").await?;
        let mask = u8::from_str_radix(response.trim(), 16).map_err(|_| {
            InstrumentError::InvalidRelayResponse {
                response: response.clone(),
            }
        })?;
        if mask & !0x0F != 0 {
            return Err(InstrumentError::InvalidRelayResponse { response });
        }
        Ok(RelayObservation {
            controller_state: std::array::from_fn(|index| {
                if mask & (1 << index) == 0 {
                    RelayState::Off
                } else {
                    RelayState::On
                }
            }),
            physical_contacts_observed: false,
        })
    }

    async fn command(&mut self, command: &str) -> Result<String, InstrumentError> {
        let transcript = timeout(self.timeout, async {
            self.stream
                .write_all(command.as_bytes())
                .await
                .map_err(|source| InstrumentError::Io {
                    action: "writing Numato command",
                    source,
                })?;
            self.stream
                .write_all(b"\r")
                .await
                .map_err(|source| InstrumentError::Io {
                    action: "terminating Numato command",
                    source,
                })?;
            self.stream
                .flush()
                .await
                .map_err(|source| InstrumentError::Io {
                    action: "flushing Numato command",
                    source,
                })?;
            self.read_prompt().await
        })
        .await
        .map_err(|_| InstrumentError::Timeout {
            operation: "executing Numato command",
        })??;
        parse_transcript(command, &transcript)
    }

    async fn read_prompt(&mut self) -> Result<String, InstrumentError> {
        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let count =
                self.stream
                    .read(&mut byte)
                    .await
                    .map_err(|source| InstrumentError::Io {
                        action: "reading Numato response",
                        source,
                    })?;
            if count == 0 {
                return Err(InstrumentError::EndOfStream {
                    operation: "reading Numato response",
                });
            }
            let byte = byte.first().copied().ok_or(InstrumentError::EndOfStream {
                operation: "reading Numato response",
            })?;
            response.push(byte);
            if response.len() > RESPONSE_LIMIT {
                return Err(InstrumentError::FrameTooLarge {
                    limit: RESPONSE_LIMIT,
                });
            }
            if byte == b'>' {
                return String::from_utf8(response).map_err(|error| {
                    InstrumentError::MalformedResponse {
                        detail: error.to_string(),
                    }
                });
            }
        }
    }
}

impl NumatoAdapter<tokio_serial::SerialStream> {
    /// Opens the supervisor-selected CDC port. Agent/API input never reaches this boundary.
    pub fn open_bound(serial: &SerialBinding, timeout: Duration) -> Result<Self, InstrumentError> {
        let stream = tokio_serial::new(serial.path.to_string_lossy(), serial.baud_rate)
            .open_native_async()
            .map_err(|source| InstrumentError::Io {
                action: "opening supervisor-bound Numato port",
                source: source.into(),
            })?;
        Ok(Self::new(stream, timeout))
    }
}

fn parse_transcript(command: &str, transcript: &str) -> Result<String, InstrumentError> {
    let normalized = transcript.replace('\r', "\n");
    let lines = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != command && *line != ">")
        .collect::<Vec<_>>();
    match lines.as_slice() {
        [response] => Ok((*response).to_owned()),
        [] => Ok(String::new()),
        _ => Err(InstrumentError::MalformedResponse {
            detail: format!("ambiguous Numato transcript {transcript:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{NumatoAdapter, RelayState};

    #[tokio::test]
    async fn parses_echoed_readall_without_claiming_contact_feedback() {
        let (client, mut peer) = tokio::io::duplex(128);
        let responder = tokio::spawn(async move {
            let mut command = [0u8; 32];
            let _ = peer.read(&mut command).await;
            peer.write_all(b"relay readall\r\n05\r\n>")
                .await
                .unwrap_or_else(|error| panic!("write response: {error}"));
        });
        let mut adapter = NumatoAdapter::new(client, Duration::from_secs(1));
        let observation = adapter
            .read_relays()
            .await
            .unwrap_or_else(|error| panic!("read relays: {error}"));
        responder
            .await
            .unwrap_or_else(|error| panic!("responder: {error}"));
        assert_eq!(
            observation.controller_state,
            [
                RelayState::On,
                RelayState::Off,
                RelayState::On,
                RelayState::Off
            ]
        );
        assert!(!observation.physical_contacts_observed);
    }

    #[test]
    fn rejects_ambiguous_transcripts() {
        let result = super::parse_transcript("relay readall", "relay readall\r\n05\r\nextra\r\n>");
        assert!(result.is_err());
    }
}
