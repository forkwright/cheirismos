//! Deterministic, filesystem-persistent disposable instrument simulation.
//!
//! The simulator is intentionally not an in-memory mock: reopening it reads the
//! preceding flash and relay state, so reconciliation paths see the same ambiguity
//! that a supervisor restart sees. Its store is an explicit file beneath a caller
//! supplied simulator directory and never targets a physical device.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::InstrumentError;

const STORE_FILE: &str = "cheirismos-instrument-simulator.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatorFault {
    None,
    InterruptNextEffect,
    InterruptAfterBytes { bytes: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatorObservation {
    pub relay_closed: [bool; 4],
    pub flash_bytes: usize,
    pub effect_calls: u64,
    pub partial_effect_calls: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulatorState {
    flash: Vec<u8>,
    relay_closed: [bool; 4],
    effect_calls: u64,
    partial_effect_calls: u64,
    fault: SimulatorFault,
}

/// Persistent fake instruments for tests and supervisor dry-runs.
pub struct Simulator {
    store_path: PathBuf,
    state: SimulatorState,
}

impl Simulator {
    pub fn open(root: impl AsRef<Path>, flash_bytes: usize) -> Result<Self, InstrumentError> {
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|source| InstrumentError::Io {
            action: "creating simulator directory",
            source,
        })?;
        let store_path = root.join(STORE_FILE);
        let state = if store_path.exists() {
            let bytes = fs::read(&store_path).map_err(|source| InstrumentError::Io {
                action: "reading simulator store",
                source,
            })?;
            serde_json::from_slice(&bytes).map_err(|error| {
                InstrumentError::InvalidSimulatorStore {
                    detail: error.to_string(),
                }
            })?
        } else {
            let state = SimulatorState {
                flash: vec![0xFF; flash_bytes],
                relay_closed: [false; 4],
                effect_calls: 0,
                partial_effect_calls: 0,
                fault: SimulatorFault::None,
            };
            persist(&store_path, &state)?;
            state
        };
        if state.flash.len() != flash_bytes {
            return Err(InstrumentError::InvalidSimulatorStore {
                detail: format!(
                    "existing flash is {} bytes, requested {flash_bytes}",
                    state.flash.len()
                ),
            });
        }
        Ok(Self { store_path, state })
    }

    pub fn observe(&self) -> SimulatorObservation {
        SimulatorObservation {
            relay_closed: self.state.relay_closed,
            flash_bytes: self.state.flash.len(),
            effect_calls: self.state.effect_calls,
            partial_effect_calls: self.state.partial_effect_calls,
        }
    }

    pub fn inject_fault(&mut self, fault: SimulatorFault) -> Result<(), InstrumentError> {
        self.state.fault = fault;
        self.persist()
    }

    pub fn set_relay(&mut self, relay: usize, closed: bool) -> Result<(), InstrumentError> {
        if relay >= self.state.relay_closed.len() {
            return Err(InstrumentError::InvalidRelayResponse {
                response: format!("relay index {relay} outside 0..4"),
            });
        }
        self.state.effect_calls = self.state.effect_calls.saturating_add(1);
        if matches!(self.take_fault(), SimulatorFault::InterruptNextEffect) {
            self.state.partial_effect_calls = self.state.partial_effect_calls.saturating_add(1);
            self.persist()?;
            return Err(InstrumentError::DeviceRejected {
                detail: "simulated interruption before relay actuation".to_owned(),
            });
        }
        let state = self.state.relay_closed.get_mut(relay).ok_or_else(|| {
            InstrumentError::InvalidRelayResponse {
                response: format!("relay index {relay} outside 0..4"),
            }
        })?;
        *state = closed;
        self.persist()
    }

    pub fn read_flash(&self, offset: usize, length: usize) -> Result<Vec<u8>, InstrumentError> {
        let range = self.range(offset, length)?;
        self.state
            .flash
            .get(range)
            .map(ToOwned::to_owned)
            .ok_or(InstrumentError::ProtocolLimit {
                requested: length,
                limit: self.state.flash.len(),
            })
    }

    pub fn erase_flash(&mut self, offset: usize, length: usize) -> Result<(), InstrumentError> {
        let range = self.range(offset, length)?;
        let flash_len = self.state.flash.len();
        self.state.effect_calls = self.state.effect_calls.saturating_add(1);
        if !matches!(self.take_fault(), SimulatorFault::None) {
            self.state.partial_effect_calls = self.state.partial_effect_calls.saturating_add(1);
            let midpoint = range.start + ((range.end - range.start) / 2);
            self.state
                .flash
                .get_mut(range.start..midpoint)
                .ok_or(InstrumentError::ProtocolLimit {
                    requested: range.end.saturating_sub(range.start),
                    limit: flash_len,
                })?
                .fill(0xFF);
            self.persist()?;
            return Err(InstrumentError::DeviceRejected {
                detail: "simulated interrupted erase".to_owned(),
            });
        }
        self.state
            .flash
            .get_mut(range.clone())
            .ok_or(InstrumentError::ProtocolLimit {
                requested: range.end.saturating_sub(range.start),
                limit: flash_len,
            })?
            .fill(0xFF);
        self.persist()
    }

    pub fn write_flash(&mut self, offset: usize, bytes: &[u8]) -> Result<(), InstrumentError> {
        let range = self.range(offset, bytes.len())?;
        let flash_len = self.state.flash.len();
        if self
            .state
            .flash
            .get(range.clone())
            .ok_or(InstrumentError::ProtocolLimit {
                requested: range.end.saturating_sub(range.start),
                limit: flash_len,
            })?
            .iter()
            .zip(bytes)
            .any(|(existing, requested)| requested & !existing != 0)
        {
            return Err(InstrumentError::DeviceRejected {
                detail: "NOR write would change a programmed bit from zero to one; erase first"
                    .to_owned(),
            });
        }
        self.state.effect_calls = self.state.effect_calls.saturating_add(1);
        match self.take_fault() {
            SimulatorFault::None => {
                let destination = self.state.flash.get_mut(range.clone()).ok_or(
                    InstrumentError::ProtocolLimit {
                        requested: range.end.saturating_sub(range.start),
                        limit: flash_len,
                    },
                )?;
                program_nor(destination, bytes);
            }
            SimulatorFault::InterruptNextEffect => {
                self.state.partial_effect_calls = self.state.partial_effect_calls.saturating_add(1);
                self.persist()?;
                return Err(InstrumentError::DeviceRejected {
                    detail: "simulated interruption before flash write".to_owned(),
                });
            }
            SimulatorFault::InterruptAfterBytes { bytes: permitted } => {
                self.state.partial_effect_calls = self.state.partial_effect_calls.saturating_add(1);
                let count = permitted.min(bytes.len());
                let end = range
                    .start
                    .checked_add(count)
                    .ok_or(InstrumentError::ProtocolLimit {
                        requested: count,
                        limit: flash_len,
                    })?;
                let destination = self.state.flash.get_mut(range.start..end).ok_or(
                    InstrumentError::ProtocolLimit {
                        requested: count,
                        limit: flash_len,
                    },
                )?;
                let source = bytes.get(..count).ok_or(InstrumentError::ProtocolLimit {
                    requested: count,
                    limit: bytes.len(),
                })?;
                program_nor(destination, source);
                self.persist()?;
                return Err(InstrumentError::DeviceRejected {
                    detail: format!("simulated interruption after {count} bytes"),
                });
            }
        }
        self.persist()
    }

    fn range(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<std::ops::Range<usize>, InstrumentError> {
        let end = offset
            .checked_add(length)
            .ok_or(InstrumentError::ProtocolLimit {
                requested: length,
                limit: self.state.flash.len(),
            })?;
        if end > self.state.flash.len() {
            return Err(InstrumentError::ProtocolLimit {
                requested: end,
                limit: self.state.flash.len(),
            });
        }
        Ok(offset..end)
    }

    fn take_fault(&mut self) -> SimulatorFault {
        std::mem::replace(&mut self.state.fault, SimulatorFault::None)
    }

    fn persist(&self) -> Result<(), InstrumentError> {
        persist(&self.store_path, &self.state)
    }
}

fn program_nor(destination: &mut [u8], source: &[u8]) {
    for (stored, requested) in destination.iter_mut().zip(source) {
        *stored &= *requested;
    }
}

fn persist(path: &Path, state: &SimulatorState) -> Result<(), InstrumentError> {
    let encoded =
        serde_json::to_vec(state).map_err(|error| InstrumentError::InvalidSimulatorStore {
            detail: error.to_string(),
        })?;
    let temporary = path.with_extension("next");
    let mut file = fs::File::create(&temporary).map_err(|source| InstrumentError::Io {
        action: "creating simulator store",
        source,
    })?;
    file.write_all(&encoded)
        .map_err(|source| InstrumentError::Io {
            action: "writing simulator store",
            source,
        })?;
    file.sync_all().map_err(|source| InstrumentError::Io {
        action: "syncing simulator store",
        source,
    })?;
    fs::rename(&temporary, path).map_err(|source| InstrumentError::Io {
        action: "replacing simulator store",
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{Simulator, SimulatorFault};
    use crate::instruments::InstrumentError;

    #[test]
    fn simulator_persists_flash_and_relays_across_reopen() {
        let directory =
            tempdir().unwrap_or_else(|error| panic!("temporary simulator dir: {error}"));
        let mut first = Simulator::open(directory.path(), 64)
            .unwrap_or_else(|error| panic!("open simulator: {error}"));
        first
            .write_flash(4, &[1, 2, 3])
            .unwrap_or_else(|error| panic!("write: {error}"));
        first
            .set_relay(2, true)
            .unwrap_or_else(|error| panic!("relay: {error}"));
        drop(first);

        let second = Simulator::open(directory.path(), 64)
            .unwrap_or_else(|error| panic!("reopen simulator: {error}"));
        assert_eq!(
            second
                .read_flash(4, 3)
                .unwrap_or_else(|error| panic!("read: {error}")),
            [1, 2, 3]
        );
        assert!(second.observe().relay_closed[2]);
        assert_eq!(second.observe().effect_calls, 2);
    }

    #[test]
    fn interrupted_write_persists_partial_state_for_reconciliation() {
        let directory =
            tempdir().unwrap_or_else(|error| panic!("temporary simulator dir: {error}"));
        let mut simulator = Simulator::open(directory.path(), 16)
            .unwrap_or_else(|error| panic!("open simulator: {error}"));
        simulator
            .inject_fault(SimulatorFault::InterruptAfterBytes { bytes: 2 })
            .unwrap_or_else(|error| panic!("inject fault: {error}"));
        let result = simulator.write_flash(0, &[0x11, 0x22, 0x33]);
        assert!(matches!(
            result,
            Err(InstrumentError::DeviceRejected { .. })
        ));
        drop(simulator);

        let reopened = Simulator::open(directory.path(), 16)
            .unwrap_or_else(|error| panic!("reopen simulator: {error}"));
        assert_eq!(
            reopened
                .read_flash(0, 3)
                .unwrap_or_else(|error| panic!("read: {error}")),
            [0x11, 0x22, 0xFF]
        );
        assert_eq!(reopened.observe().partial_effect_calls, 1);
    }

    #[test]
    fn simulator_refuses_zero_to_one_without_erase() {
        let directory =
            tempdir().unwrap_or_else(|error| panic!("temporary simulator dir: {error}"));
        let mut simulator = Simulator::open(directory.path(), 16)
            .unwrap_or_else(|error| panic!("open simulator: {error}"));
        simulator
            .write_flash(0, &[0x00])
            .unwrap_or_else(|error| panic!("program: {error}"));
        let result = simulator.write_flash(0, &[0xFF]);
        assert!(matches!(
            result,
            Err(InstrumentError::DeviceRejected { .. })
        ));
        assert_eq!(
            simulator
                .read_flash(0, 1)
                .unwrap_or_else(|error| panic!("read: {error}")),
            [0x00]
        );
    }
}
