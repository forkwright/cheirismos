//! Supervisor-owned device sessions. Admission and durable intent precede this boundary.
//!
//! Receipts retain observed identity and synchronized evidence. Transport failure
//! invalidates the session; reconciliation only observes and never repeats effects.

mod bus;
mod identity;
mod preflight;
mod simulated;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio_serial::SerialStream;

use crate::domain::{
    ArtifactDigest, EvidenceEnvelope, InstrumentId, Observation, Operation, OperationReceipt,
};
use crate::evidence::{ArtifactStore, EvidenceSource};
use crate::instruments::{
    Bpio2Adapter, InstrumentConfig, NumatoAdapter, RelayState, Simulator, VideoAdapter,
    capture_video,
};
use crate::supervisor::{
    ArtifactResolver, Backend, BackendError, DispatchRequest, ReconciliationRequest,
};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlashIdentity {
    pub jedec_id: [u8; 3],
    pub sfdp_digest: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceBinding {
    pub config: InstrumentConfig,
    pub target_fingerprint: ArtifactDigest,
    pub fixture_revision: ArtifactDigest,
    #[serde(default)]
    pub flash_identity: Option<FlashIdentity>,
}

enum Connected {
    Bpio2(Bpio2Adapter<SerialStream>),
    Numato(NumatoAdapter<SerialStream>),
    Simulator(Simulator),
    Video(VideoAdapter),
}

struct DeviceSession {
    binding: DeviceBinding,
    connection: Mutex<Option<Connected>>,
}

pub struct DeviceBackend {
    sessions: BTreeMap<InstrumentId, DeviceSession>,
    state_dir: PathBuf,
    artifacts: Arc<ArtifactStore>,
    runtime: Handle,
}

impl DeviceBackend {
    pub fn open(
        bindings: BTreeMap<InstrumentId, DeviceBinding>,
        state_dir: PathBuf,
        artifacts: Arc<ArtifactStore>,
        runtime: Handle,
    ) -> Result<Self, BackendError> {
        identity::validate_unique_physical_identities(
            bindings.values().map(|binding| &binding.config),
        )?;
        for binding in bindings.values() {
            identity::validate_config(&binding.config)?;
        }
        Ok(Self {
            sessions: bindings
                .into_iter()
                .map(|(id, binding)| {
                    (
                        id,
                        DeviceSession {
                            binding,
                            connection: Mutex::new(None),
                        },
                    )
                })
                .collect(),
            state_dir,
            artifacts,
            runtime,
        })
    }

    pub fn inventory(&self) -> Value {
        json!(
            self.sessions
                .iter()
                .map(|(id, session)| json!({
                    "instrument": id,
                    "config": session.binding.config,
                    "qualification": "requires_commissioned_profile",
                }))
                .collect::<Vec<_>>()
        )
    }

    pub fn inspect(&self, instrument: &InstrumentId) -> Result<Observation, BackendError> {
        let session = self.session(instrument)?;
        let mut connection = session.connection.lock().map_err(transport)?;
        let result = self.runtime.block_on(async {
            tokio::time::timeout(DISCOVERY_TIMEOUT, async {
                self.connect(session, &mut connection)?;
                identity::observe(
                    &session.binding,
                    connection
                        .as_mut()
                        .ok_or_else(|| malformed("missing device session"))?,
                )
                .await
            })
            .await
        });
        match result {
            Ok(Ok(mut observation)) => {
                let evidence = self
                    .artifacts
                    .publish(
                        &serde_json::to_vec(&observation).map_err(malformed)?,
                        EvidenceSource::Commissioning(instrument.clone()),
                    )
                    .map_err(transport)?;
                observation.evidence = Some(evidence);
                Ok(observation)
            }
            Ok(Err(error)) => {
                *connection = None;
                Err(error)
            }
            Err(_) => {
                *connection = None;
                Err(BackendError::Timeout {
                    message: "instrument discovery deadline".into(),
                })
            }
        }
    }

    fn session(&self, instrument: &InstrumentId) -> Result<&DeviceSession, BackendError> {
        self.sessions
            .get(instrument)
            .ok_or_else(|| malformed(format!("unconfigured instrument {instrument}")))
    }

    fn connect(
        &self,
        session: &DeviceSession,
        connection: &mut Option<Connected>,
    ) -> Result<(), BackendError> {
        identity::verify_usb(&session.binding.config)?;
        if connection.is_some() {
            return Ok(());
        }
        *connection = Some(match &session.binding.config {
            InstrumentConfig::Bpio2(config) => Connected::Bpio2(
                Bpio2Adapter::open_bound(&config.serial, DISCOVERY_TIMEOUT).map_err(transport)?,
            ),
            InstrumentConfig::Numato(config) => Connected::Numato(
                NumatoAdapter::open_bound(&config.serial, DISCOVERY_TIMEOUT).map_err(transport)?,
            ),
            InstrumentConfig::Simulator(config) => Connected::Simulator(
                Simulator::open(
                    self.state_dir.join(
                        identity::configured_physical_identity(&session.binding.config)?.as_str(),
                    ),
                    config.flash_bytes,
                )
                .map_err(transport)?,
            ),
            InstrumentConfig::Video(config) => {
                Connected::Video(VideoAdapter::new(config).map_err(transport)?)
            }
        });
        Ok(())
    }

    fn publish(
        &self,
        request: &DispatchRequest,
        fingerprint: ArtifactDigest,
        mut body: Value,
        bytes: Option<Vec<u8>>,
    ) -> Result<Observation, BackendError> {
        if let Some(bytes) = bytes {
            if bytes.len() > MAX_EVIDENCE_BYTES {
                return Err(malformed("observation exceeds evidence size limit"));
            }
            let digest = self
                .artifacts
                .publish(&bytes, EvidenceSource::Attempt(request.attempt.clone()))
                .map_err(transport)?;
            body["artifact"] = json!(digest);
            body["artifact_bytes"] = json!(bytes.len());
        }
        body["instrument_fingerprint"] = json!(fingerprint);
        body["target_identity_basis"] = json!("operator_commissioned_fixture_binding");
        let mut observation = Observation {
            captured_at: jiff::Timestamp::now().to_string(),
            source_fingerprint: fingerprint,
            body,
            evidence: None,
        };
        let envelope = EvidenceEnvelope {
            attempt: request.attempt.clone(),
            challenge: request.evidence_challenge.clone(),
            phase: request.evidence_phase,
            observation: observation.clone(),
        };
        let evidence = self
            .artifacts
            .publish(
                &serde_json::to_vec(&envelope).map_err(malformed)?,
                EvidenceSource::Attempt(request.attempt.clone()),
            )
            .map_err(transport)?;
        observation.evidence = Some(evidence);
        Ok(observation)
    }

    fn run(
        &self,
        request: &DispatchRequest,
        artifacts: &dyn ArtifactResolver,
        reconcile: bool,
    ) -> Result<OperationReceipt, BackendError> {
        let started = Instant::now();
        if request.deadline_milliseconds == 0 {
            return Err(malformed("zero operation deadline"));
        }
        if let Operation::Wait { milliseconds, .. } = &request.operation {
            if *milliseconds > request.deadline_milliseconds {
                return Err(malformed("wait exceeds operation deadline"));
            }
            if !reconcile {
                std::thread::sleep(Duration::from_millis(*milliseconds));
            }
            let observation = self.publish(request, ArtifactDigest::sha256(b"cheirismos:monotonic-clock:v1"),
                json!({"source":"supervisor_clock","elapsed_milliseconds":started.elapsed().as_millis(),"reconciliation":reconcile}), None)?;
            return Ok(if reconcile {
                OperationReceipt::Unknown {
                    reason: "current clock observation cannot prove the interrupted wait interval"
                        .into(),
                    observation: Some(observation),
                }
            } else {
                OperationReceipt::Completed { observation }
            });
        }
        let id = request
            .operation
            .instrument()
            .ok_or_else(|| malformed("operation has no instrument"))?;
        let session = self.session(id)?;
        if session.binding.target_fingerprint != request.expected_target_fingerprint
            || session.binding.fixture_revision != request.expected_fixture_revision
        {
            return Ok(OperationReceipt::Rejected {
                reason: "fixture or target binding changed since review".into(),
            });
        }
        let configuration_digest =
            ArtifactDigest::sha256(&serde_json::to_vec(&session.binding).map_err(malformed)?);
        if request
            .expected_instrument_configurations
            .iter()
            .find(|(instrument, _)| instrument == id)
            .map(|(_, digest)| digest)
            != Some(&configuration_digest)
        {
            return Ok(OperationReceipt::Rejected {
                reason: "instrument configuration differs from the reviewed configuration digest"
                    .into(),
            });
        }
        let mut connection = session.connection.lock().map_err(transport)?;
        let mut deadline = Duration::from_millis(request.deadline_milliseconds);
        if let Some(expires) = request.interlocks_valid_until {
            let left = expires
                .as_millisecond()
                .checked_sub(jiff::Timestamp::now().as_millisecond())
                .and_then(|left| u64::try_from(left).ok())
                .filter(|left| *left > 0);
            let Some(left) = left else {
                return Ok(OperationReceipt::Rejected {
                    reason: "live interlock expired before device access".into(),
                });
            };
            deadline = deadline.min(started.elapsed() + Duration::from_millis(left));
        }
        let remaining =
            deadline
                .checked_sub(started.elapsed())
                .ok_or_else(|| BackendError::Timeout {
                    message: "device session wait exhausted deadline".into(),
                })?;
        let result = self.runtime.block_on(async {
            tokio::time::timeout(remaining, async {
                self.connect(session, &mut connection)?;
                let connected = connection.as_mut().ok_or_else(|| malformed("missing device session"))?;
                let observed = identity::observe(&session.binding, connected).await?;
                let expected = request.expected_instrument_fingerprints.iter().find(|(instrument, _)| instrument == id).map(|(_, digest)| digest);
                if expected != Some(&observed.source_fingerprint) {
                    return Ok(OperationReceipt::Rejected { reason: "observed instrument identity/configuration differs from reviewed binding".into() });
                }
                if request.interlocks_valid_until.is_some_and(|expires| jiff::Timestamp::now() >= expires) {
                    return Ok(OperationReceipt::Rejected { reason: "live interlock expired during instrument identity verification".into() });
                }
                let expected_physical = request.expected_instrument_physical_identities.iter().find(|(instrument, _)| instrument == id).map(|(_, digest)| digest.as_str());
                if observed.body.get("physical_identity").and_then(Value::as_str) != expected_physical {
                    return Ok(OperationReceipt::Rejected { reason: "physical instrument differs from the commissioned lease identity".into() });
                }
                let result = match connected {
                    Connected::Bpio2(adapter) => bus::execute(adapter, &session.binding, &request.operation, artifacts, reconcile, request.configure_instrument).await?,
                    Connected::Numato(adapter) => relay_operation(adapter, &session.binding.config, &request.operation, reconcile).await?,
                    Connected::Simulator(simulator) => simulated::execute(simulator, &request.operation, artifacts, reconcile)?,
                    Connected::Video(_) => {
                        let InstrumentConfig::Video(config) = &session.binding.config else { return Err(malformed("video configuration mismatch")); };
                        match &request.operation {
                            Operation::InstrumentStatus { .. } => ResultData::observation(observed.body.clone()),
                            Operation::VideoCapture { .. } => {
                                let mut config = config.clone();
                                let left = deadline.checked_sub(started.elapsed()).ok_or_else(|| BackendError::Timeout { message: "video capture deadline exhausted".into() })?;
                                config.frame_timeout_milliseconds = config.frame_timeout_milliseconds.min(left.as_millis().try_into().map_err(malformed)?);
                                let frame = capture_video(&config).map_err(transport)?;
                                ResultData::bytes(frame.png, json!({"media_type":"image/png","usb_identity":frame.identity.usb_identity,"interpretation":null,"reconciliation":reconcile}))
                            }
                            _ => return Err(malformed("operation is unsupported by video capture instrument")),
                        }
                    }
                };
                let observation = self.publish(request, observed.source_fingerprint, result.body, result.bytes)?;
                Ok(match result.partial {
                    Some(reason) if reconcile => OperationReceipt::Unknown { observation: Some(observation), reason },
                    Some(reason) => OperationReceipt::Partial { observation, reason },
                    None => OperationReceipt::Completed { observation },
                })
            }).await
        });
        match result {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(error)) => {
                *connection = None;
                Err(error)
            }
            Err(_) => {
                *connection = None;
                Err(BackendError::Timeout {
                    message:
                        "operation deadline expired; session discarded, effect may be incomplete"
                            .into(),
                })
            }
        }
    }
}

impl Backend for DeviceBackend {
    fn preflight(
        &self,
        operation: &Operation,
        profile: &crate::domain::CommissionedProfile,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        if let Operation::Wait { milliseconds, .. } = operation {
            if *milliseconds == 0 {
                return Err(malformed("wait duration must be positive"));
            }
            return Ok(());
        }
        let instrument = operation
            .instrument()
            .ok_or_else(|| malformed("operation has no instrument"))?;
        let binding = &self.session(instrument)?.binding;
        let expected = profile
            .instrument(instrument)
            .ok_or_else(|| malformed("instrument is absent from commissioned profile"))?;
        if binding.target_fingerprint != profile.target_fingerprint
            || binding.fixture_revision != profile.fixture_revision
            || ArtifactDigest::sha256(&serde_json::to_vec(binding).map_err(malformed)?)
                != expected.configuration_digest
            || identity::configured_physical_identity(&binding.config)?
                != expected.physical_identity
        {
            return Err(malformed(
                "configured target, fixture, or instrument binding differs from the commissioned profile",
            ));
        }
        preflight::validate(binding, operation, artifacts)
    }

    fn execute(
        &self,
        request: &DispatchRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError> {
        self.run(request, artifacts, false)
    }

    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError> {
        self.run(&request.dispatch, artifacts, true)
    }
}

impl crate::service::api::InstrumentInspector for DeviceBackend {
    fn inspect(&self, instrument: &InstrumentId) -> Result<Observation, String> {
        DeviceBackend::inspect(self, instrument).map_err(|error| error.to_string())
    }

    fn inventory(&self) -> Value {
        DeviceBackend::inventory(self)
    }
}

struct ResultData {
    body: Value,
    bytes: Option<Vec<u8>>,
    partial: Option<String>,
}

impl ResultData {
    fn observation(body: Value) -> Self {
        Self {
            body,
            bytes: None,
            partial: None,
        }
    }
    fn bytes(bytes: Vec<u8>, body: Value) -> Self {
        Self {
            body,
            bytes: Some(bytes),
            partial: None,
        }
    }
}

async fn relay_operation(
    adapter: &mut NumatoAdapter<SerialStream>,
    config: &InstrumentConfig,
    operation: &Operation,
    reconcile: bool,
) -> Result<ResultData, BackendError> {
    let InstrumentConfig::Numato(config) = config else {
        return Err(malformed("relay adapter configuration mismatch"));
    };
    let (relay, expected) = match operation {
        Operation::InstrumentStatus { .. } => (None, None),
        Operation::RelayRead { relay, .. } => (Some(*relay), None),
        Operation::RelaySet { relay, closed, .. } => (Some(*relay), Some(*closed)),
        _ => {
            return Err(malformed(
                "operation is unsupported by Numato relay controller",
            ));
        }
    };
    if let Some(relay) = relay {
        let relay = u8::try_from(relay).map_err(malformed)?;
        if !config.relay_map.values().any(|mapped| *mapped == relay) {
            return Err(malformed("relay is outside configured fixture map"));
        }
        if let Some(closed) = expected.filter(|_| !reconcile) {
            adapter
                .set_relay(
                    relay,
                    if closed {
                        RelayState::On
                    } else {
                        RelayState::Off
                    },
                )
                .await
                .map_err(transport)?;
        }
    }
    let observation = adapter.read_relays().await.map_err(transport)?;
    let states = observation
        .controller_state
        .map(|state| state == RelayState::On);
    let mismatch = relay
        .zip(expected)
        .is_some_and(|(relay, expected)| states.get(usize::from(relay)) != Some(&expected));
    Ok(ResultData {
        body: json!({"controller_relay_closed":states,"physical_contacts_observed":false,"reconciliation":reconcile,"proves_original_actuation":false}),
        bytes: None,
        partial: mismatch.then(|| "controller state differs from requested state".into()),
    })
}

fn source_bytes(
    artifacts: &dyn ArtifactResolver,
    digest: &ArtifactDigest,
    length: u32,
) -> Result<Vec<u8>, BackendError> {
    let artifact = artifacts.resolve(digest).map_err(transport)?;
    if artifact.as_bytes().len() != length as usize
        || artifact.as_bytes().len() > MAX_EVIDENCE_BYTES
    {
        return Err(malformed(
            "candidate artifact length must exactly match planned region",
        ));
    }
    Ok(artifact.as_bytes().to_vec())
}

fn malformed(message: impl std::fmt::Display) -> BackendError {
    BackendError::Malformed {
        message: message.to_string(),
    }
}
fn transport(message: impl std::fmt::Display) -> BackendError {
    BackendError::Transport {
        message: message.to_string(),
    }
}
