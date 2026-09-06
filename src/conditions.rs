//! Pure observation predicates and live interlock contracts.
//!
//! This module validates and evaluates typed conditions only. It neither reads
//! hardware nor admits an operation; the supervisor wires these contracts into
//! durable authorization separately.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use snafu::Snafu;

use crate::domain::{ArtifactDigest, EffectPermission, Observation, Operation};

/// One RFC 6901 JSON Pointer rooted at [`Observation::body`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct JsonPointer(String);

impl JsonPointer {
    /// Parse a pointer rooted at `Observation.body`.
    ///
    /// The empty pointer selects the complete body. Nonempty pointers must
    /// start with `/` and may escape only `~` as `~0` and `/` as `~1`.
    pub fn try_new(pointer: impl Into<String>) -> Result<Self, ConditionError> {
        let pointer = pointer.into();
        if pointer.len() > 512 {
            return Err(ConditionError::InvalidPointer {
                pointer,
                reason: "exceeds 512 bytes".to_owned(),
            });
        }
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(ConditionError::InvalidPointer {
                pointer,
                reason: "must be empty or start with '/'".to_owned(),
            });
        }
        for segment in pointer.split('/').skip(1) {
            validate_pointer_segment(segment, &pointer)?;
        }
        Ok(Self(pointer))
    }

    /// Return the canonical pointer spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn resolve<'a>(&self, body: &'a Value) -> Result<&'a Value, ConditionError> {
        let mut current = body;
        for encoded in self.0.split('/').skip(1) {
            let segment = unescape_pointer_segment(encoded, &self.0)?;
            current = match current {
                Value::Object(object) => {
                    object
                        .get(&segment)
                        .ok_or_else(|| ConditionError::MissingPointer {
                            pointer: self.0.clone(),
                        })?
                }
                Value::Array(values) => {
                    let index = parse_array_index(&segment).ok_or_else(|| {
                        ConditionError::MissingPointer {
                            pointer: self.0.clone(),
                        }
                    })?;
                    values
                        .get(index)
                        .ok_or_else(|| ConditionError::MissingPointer {
                            pointer: self.0.clone(),
                        })?
                }
                _ => {
                    return Err(ConditionError::MissingPointer {
                        pointer: self.0.clone(),
                    });
                }
            };
        }
        Ok(current)
    }
}

impl TryFrom<&str> for JsonPointer {
    type Error = ConditionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<String> for JsonPointer {
    type Error = ConditionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl<'de> Deserialize<'de> for JsonPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One typed assertion evaluated against an observation value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CheckTest {
    /// Require a boolean value equal to `expected`.
    Boolean {
        /// Expected boolean value.
        expected: bool,
    },
    /// Require an integer in the inclusive declared range.
    IntegerRange {
        /// Inclusive lower bound.
        minimum: i64,
        /// Inclusive upper bound.
        maximum: i64,
    },
    /// Require a string equal to `expected`.
    TextEquals {
        /// Expected text.
        expected: String,
    },
    /// Require a SHA-256 artifact digest string equal to `expected`.
    ArtifactDigestEquals {
        /// Expected typed artifact digest.
        expected: ArtifactDigest,
    },
}

impl CheckTest {
    fn validate(&self) -> Result<(), ConditionError> {
        if let Self::IntegerRange { minimum, maximum } = self
            && minimum > maximum
        {
            return Err(ConditionError::InvalidRange {
                minimum: *minimum,
                maximum: *maximum,
            });
        }
        Ok(())
    }
}

/// One validated condition rooted at [`Observation::body`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationCheck {
    pointer: JsonPointer,
    test: CheckTest,
}

impl ObservationCheck {
    /// Construct one validated observation condition.
    pub fn try_new(pointer: JsonPointer, test: CheckTest) -> Result<Self, ConditionError> {
        test.validate()?;
        Ok(Self { pointer, test })
    }

    /// Return the body-rooted pointer selected by this check.
    #[must_use]
    pub fn pointer(&self) -> &JsonPointer {
        &self.pointer
    }

    /// Return the typed test applied to the selected value.
    #[must_use]
    pub fn test(&self) -> &CheckTest {
        &self.test
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObservationCheck {
    pointer: JsonPointer,
    test: CheckTest,
}

impl<'de> Deserialize<'de> for ObservationCheck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawObservationCheck::deserialize(deserializer)?;
        Self::try_new(raw.pointer, raw.test).map_err(serde::de::Error::custom)
    }
}

/// A bounded, read-only observation that must satisfy checks before dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveInterlock {
    effects: BTreeSet<EffectPermission>,
    observation: Operation,
    checks: Vec<ObservationCheck>,
    maximum_age_milliseconds: u64,
}

impl LiveInterlock {
    /// Construct a validated interlock contract.
    pub fn try_new(
        effects: BTreeSet<EffectPermission>,
        observation: Operation,
        checks: Vec<ObservationCheck>,
        maximum_age_milliseconds: u64,
    ) -> Result<Self, ConditionError> {
        let interlock = Self {
            effects,
            observation,
            checks,
            maximum_age_milliseconds,
        };
        interlock.validate()?;
        Ok(interlock)
    }

    /// Return effects gated by this interlock.
    #[must_use]
    pub fn effects(&self) -> &BTreeSet<EffectPermission> {
        &self.effects
    }

    /// Return the exact read-only operation that supplies this interlock.
    #[must_use]
    pub fn observation(&self) -> &Operation {
        &self.observation
    }

    /// Return predicates that must hold on the fresh observation.
    #[must_use]
    pub fn checks(&self) -> &[ObservationCheck] {
        &self.checks
    }

    /// Return the inclusive maximum observation age.
    #[must_use]
    pub const fn maximum_age_milliseconds(&self) -> u64 {
        self.maximum_age_milliseconds
    }

    fn validate(&self) -> Result<(), ConditionError> {
        if self.effects.is_empty() {
            return Err(ConditionError::EmptyInterlockEffects);
        }
        if self.checks.is_empty() {
            return Err(ConditionError::EmptyInterlockChecks);
        }
        if self.maximum_age_milliseconds == 0 {
            return Err(ConditionError::InvalidMaximumAge);
        }
        if !is_read_only_observation(&self.observation) {
            return Err(ConditionError::InterlockOperationHasEffects {
                operation: format!("{:?}", self.observation),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLiveInterlock {
    effects: BTreeSet<EffectPermission>,
    observation: Operation,
    checks: Vec<ObservationCheck>,
    maximum_age_milliseconds: u64,
}

impl<'de> Deserialize<'de> for LiveInterlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawLiveInterlock::deserialize(deserializer)?;
        Self::try_new(
            raw.effects,
            raw.observation,
            raw.checks,
            raw.maximum_age_milliseconds,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Fail-closed errors while parsing or evaluating observation conditions.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConditionError {
    /// A body-rooted JSON Pointer is malformed.
    #[snafu(display("invalid observation JSON Pointer {pointer:?}: {reason}"))]
    InvalidPointer {
        /// Rejected pointer spelling.
        pointer: String,
        /// Exact validation reason.
        reason: String,
    },
    /// An integer range has its lower bound above its upper bound.
    #[snafu(display("invalid integer range {minimum}..={maximum}"))]
    InvalidRange {
        /// Declared lower bound.
        minimum: i64,
        /// Declared upper bound.
        maximum: i64,
    },
    /// A selected body value does not exist.
    #[snafu(display("observation has no value at JSON Pointer {pointer:?}"))]
    MissingPointer {
        /// Missing pointer spelling.
        pointer: String,
    },
    /// A selected value has the wrong JSON type.
    #[snafu(display("observation value at {pointer:?} has type {actual}, expected {expected}"))]
    WrongType {
        /// Pointer to the selected value.
        pointer: String,
        /// Expected JSON type.
        expected: &'static str,
        /// Actual JSON type.
        actual: &'static str,
    },
    /// A selected value exists but does not satisfy its predicate.
    #[snafu(display(
        "observation value at {pointer:?} did not satisfy {expected}; observed {actual}"
    ))]
    Mismatch {
        /// Pointer to the selected value.
        pointer: String,
        /// Predicate expectation.
        expected: String,
        /// Bounded JSON rendering of the observed value.
        actual: String,
    },
    /// An interlock names no effects.
    #[snafu(display("live interlock must gate at least one effect"))]
    EmptyInterlockEffects,
    /// An interlock names no predicates.
    #[snafu(display("live interlock must contain at least one check"))]
    EmptyInterlockChecks,
    /// An interlock permits no finite freshness interval.
    #[snafu(display("live interlock maximum_age_milliseconds must be positive"))]
    InvalidMaximumAge,
    /// An interlock observation could itself change a target.
    #[snafu(display("live interlock observation is not read-only: {operation}"))]
    InterlockOperationHasEffects {
        /// Debug representation of rejected operation.
        operation: String,
    },
    /// The supplied observation belongs to a different operation.
    #[snafu(display("live interlock observation operation differs from its declared operation"))]
    InterlockOperationMismatch,
    /// The supplied observation is older than its contract permits.
    #[snafu(display("live interlock observation age {actual}ms exceeds {maximum}ms"))]
    StaleInterlockObservation {
        /// Observed age in milliseconds.
        actual: u64,
        /// Maximum permitted age in milliseconds.
        maximum: u64,
    },
}

/// Evaluate every check against one observation body.
///
/// # Errors
///
/// Returns an error for a missing value, wrong JSON type, or failed predicate.
pub fn evaluate_checks(
    observation: &Observation,
    checks: &[ObservationCheck],
) -> Result<(), ConditionError> {
    for check in checks {
        let value = check.pointer.resolve(&observation.body)?;
        evaluate_test(check.pointer.as_str(), value, &check.test)?;
    }
    Ok(())
}

/// Validate one exact, fresh observation against its interlock contract.
///
/// # Errors
///
/// Returns an error when the operation differs, evidence is stale, or a
/// predicate fails. Dispatch sequencing remains a supervisor responsibility.
pub fn validate_interlock_observation(
    interlock: &LiveInterlock,
    operation: &Operation,
    observation: &Observation,
    age_milliseconds: u64,
) -> Result<(), ConditionError> {
    interlock.validate()?;
    if interlock.observation != *operation {
        return Err(ConditionError::InterlockOperationMismatch);
    }
    if age_milliseconds > interlock.maximum_age_milliseconds {
        return Err(ConditionError::StaleInterlockObservation {
            actual: age_milliseconds,
            maximum: interlock.maximum_age_milliseconds,
        });
    }
    evaluate_checks(observation, &interlock.checks)
}

fn validate_pointer_segment(segment: &str, pointer: &str) -> Result<(), ConditionError> {
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(ConditionError::InvalidPointer {
                pointer: pointer.to_owned(),
                reason: "uses an escape other than ~0 or ~1".to_owned(),
            });
        }
    }
    Ok(())
}

fn unescape_pointer_segment(segment: &str, pointer: &str) -> Result<String, ConditionError> {
    validate_pointer_segment(segment, pointer)?;
    Ok(segment.replace("~1", "/").replace("~0", "~"))
}

fn parse_array_index(segment: &str) -> Option<usize> {
    if segment.is_empty() || (segment.len() > 1 && segment.starts_with('0')) {
        return None;
    }
    segment.parse().ok()
}

fn is_read_only_observation(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::InstrumentStatus { .. }
            | Operation::AdcRead { .. }
            | Operation::RelayRead { .. }
    )
}

fn evaluate_test(pointer: &str, value: &Value, test: &CheckTest) -> Result<(), ConditionError> {
    match test {
        CheckTest::Boolean { expected } => {
            let actual = value
                .as_bool()
                .ok_or_else(|| wrong_type(pointer, "boolean", value))?;
            if actual == *expected {
                Ok(())
            } else {
                mismatch(pointer, format!("boolean {expected}"), value)
            }
        }
        CheckTest::IntegerRange { minimum, maximum } => {
            let actual = value
                .as_i64()
                .ok_or_else(|| wrong_type(pointer, "integer", value))?;
            if (*minimum..=*maximum).contains(&actual) {
                Ok(())
            } else {
                mismatch(pointer, format!("integer in {minimum}..={maximum}"), value)
            }
        }
        CheckTest::TextEquals { expected } => {
            let actual = value
                .as_str()
                .ok_or_else(|| wrong_type(pointer, "string", value))?;
            if actual == expected {
                Ok(())
            } else {
                mismatch(pointer, format!("text {expected:?}"), value)
            }
        }
        CheckTest::ArtifactDigestEquals { expected } => {
            let actual = value
                .as_str()
                .ok_or_else(|| wrong_type(pointer, "string", value))?;
            let matches = ArtifactDigest::try_from(actual)
                .map(|digest| digest == *expected)
                .unwrap_or(false);
            if matches {
                Ok(())
            } else {
                mismatch(pointer, format!("artifact digest {expected}"), value)
            }
        }
    }
}

fn wrong_type(pointer: &str, expected: &'static str, value: &Value) -> ConditionError {
    ConditionError::WrongType {
        pointer: pointer.to_owned(),
        expected,
        actual: json_type(value),
    }
}

fn mismatch(pointer: &str, expected: String, value: &Value) -> Result<(), ConditionError> {
    Err(ConditionError::Mismatch {
        pointer: pointer.to_owned(),
        expected,
        actual: render_value(value),
    })
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn render_value(value: &Value) -> String {
    let rendered = value.to_string();
    const LIMIT: usize = 160;
    if rendered.chars().count() <= LIMIT {
        rendered
    } else {
        format!("{}…", rendered.chars().take(LIMIT).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::{
        ArtifactDigest, CheckTest, ConditionError, EffectPermission, JsonPointer, LiveInterlock,
        Observation, ObservationCheck, Operation, evaluate_checks, validate_interlock_observation,
    };
    use crate::domain::{InstrumentId, TargetId};

    fn id<T>(value: &str) -> T
    where
        T: TryFrom<String>,
        <T as TryFrom<String>>::Error: std::fmt::Display,
    {
        T::try_from(value.to_owned()).unwrap_or_else(|error| panic!("fixture identifier: {error}"))
    }

    fn observation(body: serde_json::Value) -> Observation {
        Observation {
            captured_at: "2026-09-06T00:00:00Z".to_owned(),
            source_fingerprint: ArtifactDigest::sha256(b"source"),
            body,
            evidence: None,
        }
    }

    fn status() -> Operation {
        Operation::InstrumentStatus {
            target: id::<TargetId>("fixture"),
            instrument: id::<InstrumentId>("bus-pirate"),
        }
    }

    fn check(pointer: &str, test: CheckTest) -> ObservationCheck {
        ObservationCheck::try_new(
            JsonPointer::try_new(pointer).unwrap_or_else(|error| panic!("pointer: {error}")),
            test,
        )
        .unwrap_or_else(|error| panic!("check: {error}"))
    }

    #[test]
    fn pointer_accepts_rfc6901_escapes_and_rejects_other_tildes() {
        let pointer = JsonPointer::try_new("/bus~1state/~0stable")
            .unwrap_or_else(|error| panic!("escaped pointer: {error}"));
        let checks = [check(
            pointer.as_str(),
            CheckTest::Boolean { expected: true },
        )];
        evaluate_checks(
            &observation(json!({"bus/state": {"~stable": true}})),
            &checks,
        )
        .unwrap_or_else(|error| panic!("escaped pointer evaluation: {error}"));

        for invalid in ["body/value", "/bad~2escape", "/trailing~"] {
            assert!(
                JsonPointer::try_new(invalid).is_err(),
                "{invalid} must fail"
            );
        }
    }

    #[test]
    fn predicates_fail_closed_for_missing_wrong_type_range_and_digest() {
        let body = observation(json!({"ok": true, "value": 12, "digest": "not-a-digest"}));
        let missing = [check("/absent", CheckTest::Boolean { expected: true })];
        assert!(matches!(
            evaluate_checks(&body, &missing),
            Err(ConditionError::MissingPointer { .. })
        ));

        let wrong_type = [check(
            "/ok",
            CheckTest::IntegerRange {
                minimum: 0,
                maximum: 1,
            },
        )];
        assert!(matches!(
            evaluate_checks(&body, &wrong_type),
            Err(ConditionError::WrongType { .. })
        ));

        let outside = [check(
            "/value",
            CheckTest::IntegerRange {
                minimum: 13,
                maximum: 14,
            },
        )];
        assert!(matches!(
            evaluate_checks(&body, &outside),
            Err(ConditionError::Mismatch { .. })
        ));

        let digest = [check(
            "/digest",
            CheckTest::ArtifactDigestEquals {
                expected: ArtifactDigest::sha256(b"expected"),
            },
        )];
        assert!(matches!(
            evaluate_checks(&body, &digest),
            Err(ConditionError::Mismatch { .. })
        ));
    }

    #[test]
    fn malformed_ranges_are_rejected_during_deserialization() {
        let parsed = serde_json::from_value::<ObservationCheck>(json!({
            "pointer": "/value",
            "test": {"kind": "integer_range", "minimum": 4, "maximum": 3}
        }));
        assert!(parsed.is_err());

        let unknown = serde_json::from_value::<ObservationCheck>(json!({
            "pointer": "/value",
            "test": {"kind": "boolean", "expected": true},
            "unreviewed": true,
        }));
        assert!(unknown.is_err(), "condition schema must stay closed");
    }

    #[test]
    fn interlocks_require_read_only_observation_effects_checks_and_freshness() {
        let effects = BTreeSet::from([EffectPermission::PowerSet]);
        let checks = vec![check(
            "/voltage",
            CheckTest::IntegerRange {
                minimum: 3200,
                maximum: 3400,
            },
        )];
        let interlock = LiveInterlock::try_new(effects, status(), checks, 50)
            .unwrap_or_else(|error| panic!("interlock: {error}"));
        let fresh = observation(json!({"voltage": 3300}));
        validate_interlock_observation(&interlock, &status(), &fresh, 50)
            .unwrap_or_else(|error| panic!("fresh interlock: {error}"));
        assert!(matches!(
            validate_interlock_observation(&interlock, &status(), &fresh, 51),
            Err(ConditionError::StaleInterlockObservation { .. })
        ));

        let hidden_effect = Operation::PsuSet {
            target: id::<TargetId>("fixture"),
            instrument: id::<InstrumentId>("bus-pirate"),
            millivolts: 3300,
            milliamps: 50,
        };
        assert!(matches!(
            LiveInterlock::try_new(
                BTreeSet::from([EffectPermission::PowerSet]),
                hidden_effect,
                vec![check("/ok", CheckTest::Boolean { expected: true })],
                1
            ),
            Err(ConditionError::InterlockOperationHasEffects { .. })
        ));
    }

    #[test]
    fn interlock_requires_exact_operation_and_nonempty_contract() {
        assert!(matches!(
            LiveInterlock::try_new(
                BTreeSet::new(),
                status(),
                vec![check("/ok", CheckTest::Boolean { expected: true })],
                1
            ),
            Err(ConditionError::EmptyInterlockEffects)
        ));
        assert!(matches!(
            LiveInterlock::try_new(
                BTreeSet::from([EffectPermission::PowerSet]),
                status(),
                Vec::new(),
                1
            ),
            Err(ConditionError::EmptyInterlockChecks)
        ));
        assert!(matches!(
            LiveInterlock::try_new(
                BTreeSet::from([EffectPermission::PowerSet]),
                status(),
                vec![check("/ok", CheckTest::Boolean { expected: true })],
                0
            ),
            Err(ConditionError::InvalidMaximumAge)
        ));

        let interlock = LiveInterlock::try_new(
            BTreeSet::from([EffectPermission::PowerSet]),
            status(),
            vec![check("/ok", CheckTest::Boolean { expected: true })],
            1,
        )
        .unwrap_or_else(|error| panic!("interlock: {error}"));
        let other = Operation::AdcRead {
            target: id::<TargetId>("fixture"),
            instrument: id::<InstrumentId>("bus-pirate"),
            channel: 0,
        };
        assert!(matches!(
            validate_interlock_observation(
                &interlock,
                &other,
                &observation(json!({"ok": true})),
                0
            ),
            Err(ConditionError::InterlockOperationMismatch)
        ));
    }
}
