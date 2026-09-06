//! Typed facts that describe authority, intended effects, and their evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::Snafu;

pub const MAX_IDENTIFIER_LENGTH: usize = 128;

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DomainError {
    #[snafu(display(
        "{kind} must contain 1..={MAX_IDENTIFIER_LENGTH} ASCII identifier characters"
    ))]
    InvalidIdentifier { kind: &'static str },

    #[snafu(display("digest must be a 64-character lowercase SHA-256 hex string"))]
    InvalidDigest,

    #[snafu(display("budget must be finite and non-zero"))]
    InvalidBudget,

    #[snafu(display("plan has no operations"))]
    EmptyPlan,
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<(), DomainError> {
    if value == "."
        || value == ".."
        || value.is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(DomainError::InvalidIdentifier { kind });
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = DomainError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                validate_identifier(value, $kind)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = DomainError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_from(value.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(serde::de::Error::custom)
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

identifier!(TargetId, "target id");
identifier!(InstrumentId, "instrument id");
identifier!(SimulatorId, "simulator id");
identifier!(ProfileId, "profile id");
identifier!(FixtureSessionId, "fixture session id");
identifier!(GrantId, "grant id");
identifier!(PlanId, "plan id");
identifier!(CaseId, "case id");
identifier!(PrincipalId, "principal id");
identifier!(RequestId, "request id");
identifier!(AttemptId, "attempt id");
identifier!(OperationId, "operation id");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
pub struct ArtifactDigest(String);

impl ArtifactDigest {
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex::encode(digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ArtifactDigest {
    type Error = DomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(DomainError::InvalidDigest);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ArtifactDigest {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'de> Deserialize<'de> for ArtifactDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Display for ArtifactDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for ArtifactDigest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    InstrumentStatus,
    Spi,
    I2c,
    Uart,
    Gpio,
    Adc,
    Psu,
    Relay,
    Flash,
    Video,
    Wait,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EffectPermission {
    InstrumentConfigure,
    RawBusTransfer,
    UartTransmit,
    GpioDrive,
    PowerSet,
    RelayActuate,
    FlashErase,
    FlashWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub effects: u64,
    pub bytes: u64,
    pub milliseconds: u64,
}

impl Budget {
    pub const ZERO: Self = Self {
        effects: 0,
        bytes: 0,
        milliseconds: 0,
    };

    pub fn try_new(effects: u64, bytes: u64, milliseconds: u64) -> Result<Self, DomainError> {
        if effects == 0 && bytes == 0 && milliseconds == 0 {
            return Err(DomainError::InvalidBudget);
        }
        Ok(Self {
            effects,
            bytes,
            milliseconds,
        })
    }

    pub fn fits_within(&self, limit: &Self) -> bool {
        self.effects <= limit.effects
            && self.bytes <= limit.bytes
            && self.milliseconds <= limit.milliseconds
    }

    pub fn checked_sub(&self, amount: &Self) -> Option<Self> {
        Some(Self {
            effects: self.effects.checked_sub(amount.effects)?,
            bytes: self.bytes.checked_sub(amount.bytes)?,
            milliseconds: self.milliseconds.checked_sub(amount.milliseconds)?,
        })
    }

    pub fn checked_add(&self, amount: &Self) -> Option<Self> {
        Some(Self {
            effects: self.effects.checked_add(amount.effects)?,
            bytes: self.bytes.checked_add(amount.bytes)?,
            milliseconds: self.milliseconds.checked_add(amount.milliseconds)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Operation {
    InstrumentStatus {
        target: TargetId,
        instrument: InstrumentId,
    },
    SpiTransfer {
        target: TargetId,
        instrument: InstrumentId,
        tx: Vec<u8>,
        rx_bytes: u32,
    },
    I2cTransfer {
        target: TargetId,
        instrument: InstrumentId,
        address: u8,
        tx: Vec<u8>,
        rx_bytes: u32,
    },
    I2cScan {
        target: TargetId,
        instrument: InstrumentId,
    },
    UartCapture {
        target: TargetId,
        instrument: InstrumentId,
        max_bytes: u32,
    },
    UartTransmit {
        target: TargetId,
        instrument: InstrumentId,
        bytes: Vec<u8>,
    },
    GpioSet {
        target: TargetId,
        instrument: InstrumentId,
        pin: u16,
        high: bool,
    },
    AdcRead {
        target: TargetId,
        instrument: InstrumentId,
        channel: u16,
    },
    PsuSet {
        target: TargetId,
        instrument: InstrumentId,
        millivolts: u32,
        milliamps: u32,
    },
    RelaySet {
        target: TargetId,
        instrument: InstrumentId,
        relay: u16,
        closed: bool,
    },
    RelayRead {
        target: TargetId,
        instrument: InstrumentId,
        relay: u16,
    },
    FlashIdentify {
        target: TargetId,
        instrument: InstrumentId,
    },
    FlashRead {
        target: TargetId,
        instrument: InstrumentId,
        offset: u64,
        length: u32,
    },
    FlashErase {
        target: TargetId,
        instrument: InstrumentId,
        offset: u64,
        length: u32,
    },
    FlashWrite {
        target: TargetId,
        instrument: InstrumentId,
        offset: u64,
        source: ArtifactDigest,
        length: u32,
    },
    FlashVerify {
        target: TargetId,
        instrument: InstrumentId,
        offset: u64,
        source: ArtifactDigest,
        length: u32,
    },
    VideoCapture {
        target: TargetId,
        instrument: InstrumentId,
    },
    Wait {
        target: TargetId,
        milliseconds: u64,
    },
}

impl Operation {
    pub fn instrument(&self) -> Option<&InstrumentId> {
        match self {
            Self::InstrumentStatus { instrument, .. }
            | Self::SpiTransfer { instrument, .. }
            | Self::I2cTransfer { instrument, .. }
            | Self::I2cScan { instrument, .. }
            | Self::UartCapture { instrument, .. }
            | Self::UartTransmit { instrument, .. }
            | Self::GpioSet { instrument, .. }
            | Self::AdcRead { instrument, .. }
            | Self::PsuSet { instrument, .. }
            | Self::RelaySet { instrument, .. }
            | Self::RelayRead { instrument, .. }
            | Self::FlashIdentify { instrument, .. }
            | Self::FlashRead { instrument, .. }
            | Self::FlashErase { instrument, .. }
            | Self::FlashWrite { instrument, .. }
            | Self::FlashVerify { instrument, .. }
            | Self::VideoCapture { instrument, .. } => Some(instrument),
            Self::Wait { .. } => None,
        }
    }

    pub fn target(&self) -> &TargetId {
        match self {
            Self::InstrumentStatus { target, .. }
            | Self::SpiTransfer { target, .. }
            | Self::I2cTransfer { target, .. }
            | Self::I2cScan { target, .. }
            | Self::UartCapture { target, .. }
            | Self::UartTransmit { target, .. }
            | Self::GpioSet { target, .. }
            | Self::AdcRead { target, .. }
            | Self::PsuSet { target, .. }
            | Self::RelaySet { target, .. }
            | Self::RelayRead { target, .. }
            | Self::FlashIdentify { target, .. }
            | Self::FlashRead { target, .. }
            | Self::FlashErase { target, .. }
            | Self::FlashWrite { target, .. }
            | Self::FlashVerify { target, .. }
            | Self::VideoCapture { target, .. }
            | Self::Wait { target, .. } => target,
        }
    }

    pub fn capability(&self) -> Capability {
        match self {
            Self::InstrumentStatus { .. } => Capability::InstrumentStatus,
            Self::SpiTransfer { .. } => Capability::Spi,
            Self::I2cTransfer { .. } | Self::I2cScan { .. } => Capability::I2c,
            Self::UartCapture { .. } | Self::UartTransmit { .. } => Capability::Uart,
            Self::GpioSet { .. } => Capability::Gpio,
            Self::AdcRead { .. } => Capability::Adc,
            Self::PsuSet { .. } => Capability::Psu,
            Self::RelaySet { .. } | Self::RelayRead { .. } => Capability::Relay,
            Self::FlashIdentify { .. }
            | Self::FlashRead { .. }
            | Self::FlashErase { .. }
            | Self::FlashWrite { .. }
            | Self::FlashVerify { .. } => Capability::Flash,
            Self::VideoCapture { .. } => Capability::Video,
            Self::Wait { .. } => Capability::Wait,
        }
    }

    pub fn effect_permissions(&self) -> BTreeSet<EffectPermission> {
        let mut permissions = BTreeSet::new();
        match self {
            Self::SpiTransfer { .. } | Self::I2cTransfer { .. } | Self::I2cScan { .. } => {
                permissions.insert(EffectPermission::InstrumentConfigure);
                permissions.insert(EffectPermission::RawBusTransfer);
            }
            Self::UartCapture { .. } | Self::UartTransmit { .. } => {
                permissions.insert(EffectPermission::InstrumentConfigure);
                if matches!(self, Self::UartTransmit { .. }) {
                    permissions.insert(EffectPermission::UartTransmit);
                }
            }
            Self::FlashIdentify { .. }
            | Self::FlashRead { .. }
            | Self::FlashErase { .. }
            | Self::FlashWrite { .. }
            | Self::FlashVerify { .. } => {
                permissions.insert(EffectPermission::InstrumentConfigure);
                if matches!(self, Self::FlashErase { .. }) {
                    permissions.insert(EffectPermission::FlashErase);
                }
                if matches!(self, Self::FlashWrite { .. }) {
                    permissions.insert(EffectPermission::FlashWrite);
                }
            }
            Self::GpioSet { .. } => {
                permissions.insert(EffectPermission::GpioDrive);
            }
            Self::PsuSet { .. } => {
                permissions.insert(EffectPermission::PowerSet);
            }
            Self::RelaySet { .. } => {
                permissions.insert(EffectPermission::RelayActuate);
            }
            _ => {}
        }
        permissions
    }

    pub fn is_destructive(&self) -> bool {
        !self.effect_permissions().is_empty()
    }

    pub fn worst_case_budget(&self) -> Budget {
        let bytes = match self {
            Self::SpiTransfer { tx, rx_bytes, .. } | Self::I2cTransfer { tx, rx_bytes, .. } => {
                tx.len() as u64 + u64::from(*rx_bytes)
            }
            Self::UartCapture { max_bytes, .. } => u64::from(*max_bytes),
            Self::UartTransmit { bytes, .. } => bytes.len() as u64,
            Self::FlashRead { length, .. }
            | Self::FlashErase { length, .. }
            | Self::FlashWrite { length, .. }
            | Self::FlashVerify { length, .. } => u64::from(*length),
            _ => 0,
        };
        Budget {
            effects: self.effect_permissions().len() as u64,
            bytes,
            milliseconds: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrincipalRole {
    Operator,
    Admin,
    Agent,
    Reviewer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: PrincipalId,
    pub role: PrincipalRole,
    pub authentication_fingerprint: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ElectricalLimits {
    pub max_millivolts: u32,
    pub max_milliamps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegionLimits {
    pub flash_start: u64,
    pub flash_end_exclusive: u64,
}

impl RegionLimits {
    pub fn contains(&self, offset: u64, length: u32) -> bool {
        offset
            .checked_add(u64::from(length))
            .is_some_and(|end| offset >= self.flash_start && end <= self.flash_end_exclusive)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstrumentBinding {
    pub fingerprint: ArtifactDigest,
    /// Stable identity of the physical instrument. Unlike `fingerprint`, this
    /// never incorporates mutable commissioned configuration.
    pub physical_identity: ArtifactDigest,
    pub configuration_digest: ArtifactDigest,
    pub qualified_capabilities: BTreeSet<Capability>,
    pub qualified_effect_permissions: BTreeSet<EffectPermission>,
    pub qualification_evidence: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommissionedProfile {
    pub id: ProfileId,
    pub target: TargetId,
    pub target_fingerprint: ArtifactDigest,
    pub instruments: BTreeMap<InstrumentId, InstrumentBinding>,
    pub fixture_revision: ArtifactDigest,
    pub fixture_session: FixtureSessionId,
    pub permitted_capabilities: BTreeSet<Capability>,
    pub electrical_limits: ElectricalLimits,
    pub region_limits: RegionLimits,
    pub commissioning_evidence: ArtifactDigest,
    #[serde(default)]
    pub live_interlocks: Vec<crate::conditions::LiveInterlock>,
}

impl CommissionedProfile {
    pub fn instrument(&self, id: &InstrumentId) -> Option<&InstrumentBinding> {
        self.instruments.get(id)
    }

    pub fn digest(&self) -> Result<ArtifactDigest, serde_json::Error> {
        serde_json::to_vec(self).map(|encoded| ArtifactDigest::sha256(&encoded))
    }

    pub fn physical_resources(&self) -> BTreeSet<PhysicalResource> {
        let mut resources = BTreeSet::from([
            PhysicalResource::Target(self.target_fingerprint.clone()),
            PhysicalResource::Fixture(self.fixture_session.clone()),
        ]);
        resources.extend(
            self.instruments
                .values()
                .map(|binding| PhysicalResource::Instrument(binding.physical_identity.clone())),
        );
        resources
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "identity",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum PhysicalResource {
    Target(ArtifactDigest),
    Fixture(FixtureSessionId),
    Instrument(ArtifactDigest),
}

impl PhysicalResource {
    pub fn key(&self) -> String {
        match self {
            Self::Target(digest) => format!("target:{}", digest.as_str()),
            Self::Fixture(id) => format!("fixture:{}", id.as_str()),
            Self::Instrument(digest) => format!("instrument:{}", digest.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: GrantId,
    pub issued_by: PrincipalId,
    pub agent: PrincipalId,
    pub target: TargetId,
    pub profile: ProfileId,
    pub capabilities: BTreeSet<Capability>,
    pub effect_permissions: BTreeSet<EffectPermission>,
    pub remaining: Budget,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlannedOperation {
    pub operation: Operation,
    pub max_milliseconds: u64,
    #[serde(default)]
    pub postconditions: Vec<crate::conditions::ObservationCheck>,
}

impl PlannedOperation {
    pub fn worst_case_budget(&self) -> Budget {
        let mut budget = self.operation.worst_case_budget();
        budget.milliseconds = self.max_milliseconds;
        budget
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanProposal {
    pub id: PlanId,
    pub candidate_digest: ArtifactDigest,
    pub fixture_revision: ArtifactDigest,
    pub tool_digest: ArtifactDigest,
    pub target_fingerprint: ArtifactDigest,
    pub instrument_fingerprints: BTreeMap<InstrumentId, ArtifactDigest>,
    pub instrument_configuration_digests: BTreeMap<InstrumentId, ArtifactDigest>,
    pub preconditions: Vec<ArtifactDigest>,
    pub operations: Vec<PlannedOperation>,
    pub requested_by: PrincipalId,
    pub reconciliation_setup: ReconciliationSetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReconciliationSetup {
    ObservationOnly,
    ApplyReviewedInstrumentConfiguration,
}

impl PlanProposal {
    pub fn digest(&self) -> Result<ArtifactDigest, serde_json::Error> {
        serde_json::to_vec(self).map(|encoded| ArtifactDigest::sha256(&encoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewedPlan {
    pub id: PlanId,
    pub candidate_digest: ArtifactDigest,
    pub fixture_revision: ArtifactDigest,
    pub tool_digest: ArtifactDigest,
    pub target_fingerprint: ArtifactDigest,
    pub instrument_fingerprints: BTreeMap<InstrumentId, ArtifactDigest>,
    pub instrument_configuration_digests: BTreeMap<InstrumentId, ArtifactDigest>,
    pub preconditions: Vec<ArtifactDigest>,
    pub operations: Vec<PlannedOperation>,
    pub requested_by: PrincipalId,
    pub reviewed_by: PrincipalId,
    pub review_digest: ArtifactDigest,
    pub reconciliation_setup: ReconciliationSetup,
}

impl From<ReviewedPlan> for PlanProposal {
    fn from(plan: ReviewedPlan) -> Self {
        Self {
            id: plan.id,
            candidate_digest: plan.candidate_digest,
            fixture_revision: plan.fixture_revision,
            tool_digest: plan.tool_digest,
            target_fingerprint: plan.target_fingerprint,
            instrument_fingerprints: plan.instrument_fingerprints,
            instrument_configuration_digests: plan.instrument_configuration_digests,
            preconditions: plan.preconditions,
            operations: plan.operations,
            requested_by: plan.requested_by,
            reconciliation_setup: plan.reconciliation_setup,
        }
    }
}

impl ReviewedPlan {
    pub fn try_new(plan: Self) -> Result<Self, DomainError> {
        if plan.operations.is_empty() {
            return Err(DomainError::EmptyPlan);
        }
        Ok(plan)
    }

    pub fn digest(&self) -> Result<ArtifactDigest, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let serde_json::Value::Object(object) = &mut value {
            object.remove("review_digest");
        }
        serde_json::to_vec(&value).map(|encoded| ArtifactDigest::sha256(&encoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CaseFact {
    Observation {
        digest: ArtifactDigest,
    },
    Claim {
        statement: String,
        evidence: Vec<ArtifactDigest>,
    },
    Hypothesis {
        statement: String,
        supporting: Vec<ArtifactDigest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseRecord {
    pub id: CaseId,
    pub facts: Vec<CaseFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttemptState {
    Intent,
    Dispatched,
    Completed,
    Partial,
    Unknown,
    Rejected,
}

impl AttemptState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Unknown | Self::Rejected
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub captured_at: String,
    pub source_fingerprint: ArtifactDigest,
    pub body: serde_json::Value,
    pub evidence: Option<ArtifactDigest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidencePhase {
    Execution,
    Reconciliation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub attempt: AttemptId,
    pub challenge: ArtifactDigest,
    pub phase: EvidencePhase,
    pub observation: Observation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum OperationReceipt {
    Completed {
        observation: Observation,
    },
    Partial {
        observation: Observation,
        reason: String,
    },
    Unknown {
        reason: String,
        observation: Option<Observation>,
    },
    Rejected {
        reason: String,
    },
}

impl OperationReceipt {
    pub fn state(&self) -> AttemptState {
        match self {
            Self::Completed { .. } => AttemptState::Completed,
            Self::Partial { .. } => AttemptState::Partial,
            Self::Unknown { .. } => AttemptState::Unknown,
            Self::Rejected { .. } => AttemptState::Rejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub id: AttemptId,
    pub request: RequestId,
    pub grant: GrantId,
    pub plan: PlanId,
    pub operation_index: usize,
    pub plan_digest: ArtifactDigest,
    pub reserved: Budget,
    pub profile: ProfileId,
    pub profile_digest: ArtifactDigest,
    pub leased_resources: BTreeSet<PhysicalResource>,
    pub evidence_challenge: ArtifactDigest,
    pub evidence_ordinal: u64,
    pub state: AttemptState,
    pub receipt: Option<OperationReceipt>,
    pub created_at: String,
    pub updated_at: String,
}

/// An append-only witness gathered after an attempt entered an uncertain state.
/// The original attempt receipt is never replaced by these records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRecord {
    pub request: RequestId,
    pub attempt: AttemptId,
    pub ordinal: u64,
    pub challenge: ArtifactDigest,
    pub principal: PrincipalId,
    pub state: ReconciliationState,
    pub receipt: Option<OperationReceipt>,
    pub started_at: String,
    pub ended_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReconciliationState {
    Claimed,
    Completed,
    Unknown,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanRun {
    pub id: RequestId,
    pub agent: PrincipalId,
    pub grant: GrantId,
    pub plan: PlanId,
    pub steps: Vec<(AttemptId, RequestId)>,
    pub cursor: usize,
}

/// An authority-signed handoff from unresolved physical work to a separately
/// reviewed recovery experiment.  It records no assertion about the old
/// effect; the old attempt and all of its evidence remain immutable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTakeoverRecord {
    pub request: RequestId,
    pub run: RequestId,
    pub first_attempt: AttemptId,
    pub unresolved: Vec<AttemptId>,
    pub grant: GrantId,
    pub plan: PlanId,
    pub resources: BTreeSet<PhysicalResource>,
    pub justification_evidence: ArtifactDigest,
    pub authorized_by: PrincipalId,
    pub authorized_at: String,
}

/// An operator-authorized closure of a halted run which has not left an
/// uncertain physical effect.  This records why its held resources were
/// released; it never changes the receipts or reservations of the old run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HaltedRunAbandonmentRecord {
    pub request: RequestId,
    pub run: RequestId,
    pub grant: GrantId,
    pub plan: PlanId,
    /// Canonical lease keys captured in the same transaction that releases
    /// them.  They are deliberately persisted rather than inferred later.
    pub resources: BTreeSet<String>,
    pub justification_evidence: ArtifactDigest,
    pub authorized_by: PrincipalId,
    pub authorized_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier<T>(value: &str) -> T
    where
        T: TryFrom<String, Error = DomainError>,
    {
        T::try_from(value.to_owned()).unwrap_or_else(|error| panic!("identifier: {error}"))
    }

    fn binding(fingerprint: &[u8], physical_identity: ArtifactDigest) -> InstrumentBinding {
        InstrumentBinding {
            fingerprint: ArtifactDigest::sha256(fingerprint),
            physical_identity,
            configuration_digest: ArtifactDigest::sha256(b"configuration"),
            qualified_capabilities: BTreeSet::new(),
            qualified_effect_permissions: BTreeSet::new(),
            qualification_evidence: ArtifactDigest::sha256(b"qualification"),
        }
    }

    fn profile(alias: &str, binding: InstrumentBinding) -> CommissionedProfile {
        CommissionedProfile {
            id: identifier::<ProfileId>("profile"),
            target: identifier::<TargetId>("target"),
            target_fingerprint: ArtifactDigest::sha256(b"target"),
            instruments: BTreeMap::from([(identifier::<InstrumentId>(alias), binding)]),
            fixture_revision: ArtifactDigest::sha256(b"fixture"),
            fixture_session: identifier::<FixtureSessionId>("fixture-session"),
            permitted_capabilities: BTreeSet::new(),
            electrical_limits: ElectricalLimits {
                max_millivolts: 0,
                max_milliamps: 0,
            },
            region_limits: RegionLimits {
                flash_start: 0,
                flash_end_exclusive: 0,
            },
            commissioning_evidence: ArtifactDigest::sha256(b"commissioning"),
            live_interlocks: Vec::new(),
        }
    }

    #[test]
    fn aliases_with_changed_configuration_lease_one_physical_instrument() {
        let physical_identity = ArtifactDigest::sha256(b"usb:2a19:0001:bp6-a");
        let first = profile(
            "first-alias",
            binding(b"configuration-one", physical_identity.clone()),
        );
        let second = profile(
            "second-alias",
            binding(b"configuration-two", physical_identity.clone()),
        );

        assert_ne!(
            first
                .instruments
                .values()
                .next()
                .map(|value| &value.fingerprint),
            second
                .instruments
                .values()
                .next()
                .map(|value| &value.fingerprint),
        );
        assert_eq!(first.physical_resources(), second.physical_resources());
        assert!(
            first
                .physical_resources()
                .contains(&PhysicalResource::Instrument(physical_identity))
        );
    }
}
