//! Concrete, supervisor-injected instrument adapters and deterministic simulation.
//!
//! These adapters never discover device paths or apply fixture policy. The supervisor
//! supplies an already-bound byte stream and maps outcomes into durable receipts.

mod bpio2;
mod cobs;
mod config;
mod error;
mod flash;
mod numato;
mod simulator;
mod video;

pub use bpio2::{Bpio2Adapter, Bpio2Discovery, ModeConfig};
pub use config::{
    Bpio2Config, InstrumentConfig, NumatoConfig, SerialBinding, SimulatorConfig, VideoConfig,
};
pub use error::InstrumentError;
pub use flash::{AddressMode, FlashGeometry, FlashLayoutError, NorCommand, NorOperation, NorPlan};
pub use numato::{NumatoAdapter, NumatoIdentity, RelayObservation, RelayState};
pub use simulator::{Simulator, SimulatorFault, SimulatorObservation};
pub use video::{VideoAdapter, VideoFrame, VideoIdentity, capture_video, inspect_video};
