//! Enforced plan conditions over durable backend observations.

use crate::conditions::{LiveInterlock, evaluate_checks, validate_interlock_observation};
use crate::domain::{
    AttemptRecord, AttemptState, CommissionedProfile, EvidenceEnvelope, EvidencePhase, Observation,
    OperationReceipt, PlannedOperation, ReconciliationState, ReviewedPlan,
};
use crate::evidence::EvidenceSource;

use super::{Supervisor, SupervisorError};

pub(super) fn validate_plan(
    profile: &CommissionedProfile,
    plan: &ReviewedPlan,
) -> Result<(), SupervisorError> {
    for (index, planned) in plan.operations.iter().enumerate() {
        for interlock in &profile.live_interlocks {
            if !interlock
                .effects()
                .is_disjoint(&planned.operation.effect_permissions())
            {
                observation_step(plan, index, interlock)?;
            }
        }
    }
    Ok(())
}

fn observation_step(
    plan: &ReviewedPlan,
    before: usize,
    interlock: &LiveInterlock,
) -> Result<usize, SupervisorError> {
    for (index, planned) in plan.operations.iter().enumerate().take(before).rev() {
        let operation = &planned.operation;
        if operation == interlock.observation() {
            return Ok(index);
        }
        if !operation.effect_permissions().is_empty() {
            break;
        }
    }
    Err(denied(
        "live interlock needs its exact observation after the preceding effect",
    ))
}

pub(super) fn check_postconditions(
    planned: &PlannedOperation,
    receipt: OperationReceipt,
) -> OperationReceipt {
    match receipt {
        OperationReceipt::Completed { observation } => {
            match evaluate_checks(&observation, &planned.postconditions) {
                Ok(()) => OperationReceipt::Completed { observation },
                Err(error) => OperationReceipt::Partial {
                    observation,
                    reason: format!("reviewed postcondition failed: {error}"),
                },
            }
        }
        other => other,
    }
}

impl Supervisor {
    pub(super) fn check_live_interlocks(
        &self,
        attempt: &AttemptRecord,
        profile: &CommissionedProfile,
        plan: &ReviewedPlan,
    ) -> Result<Option<jiff::Timestamp>, SupervisorError> {
        let planned = plan
            .operations
            .get(attempt.operation_index)
            .ok_or_else(|| denied("interlocked operation is absent from reviewed plan"))?;
        let mut earliest_expiry = None;
        for interlock in &profile.live_interlocks {
            if interlock
                .effects()
                .is_disjoint(&planned.operation.effect_permissions())
            {
                continue;
            }
            let index = observation_step(plan, attempt.operation_index, interlock)?;
            let witness = self
                .store
                .attempt_at_step(&attempt.grant, &attempt.plan, index)
                .map_err(|source| SupervisorError::Store { source })?
                .ok_or_else(|| denied("interlock observation has no durable attempt"))?;
            if witness.state != AttemptState::Completed
                || witness.profile_digest != attempt.profile_digest
                || witness.plan_digest != attempt.plan_digest
            {
                return Err(denied(
                    "interlock observation is not completed in this reviewed run",
                ));
            }
            let observation = self.completed_observation(&witness)?;
            let captured: jiff::Timestamp = observation
                .captured_at
                .parse()
                .map_err(|_| denied("interlock observation timestamp is invalid"))?;
            let age = jiff::Timestamp::now()
                .as_millisecond()
                .checked_sub(captured.as_millisecond())
                .and_then(|age| u64::try_from(age).ok())
                .ok_or_else(|| denied("interlock observation timestamp is in the future"))?;
            validate_interlock_observation(
                interlock,
                &plan
                    .operations
                    .get(index)
                    .ok_or_else(|| denied("interlock operation is absent"))?
                    .operation,
                &observation,
                age,
            )
            .map_err(|error| denied(error.to_string()))?;
            let maximum_age = i64::try_from(interlock.maximum_age_milliseconds())
                .map_err(|_| denied("interlock age exceeds timestamp range"))?;
            let expiry_milliseconds = captured
                .as_millisecond()
                .checked_add(maximum_age)
                .ok_or_else(|| denied("interlock expiration overflows"))?;
            let expiry = jiff::Timestamp::from_millisecond(expiry_milliseconds)
                .map_err(|_| denied("interlock expiration is outside timestamp range"))?;
            earliest_expiry = Some(
                earliest_expiry.map_or(expiry, |previous: jiff::Timestamp| previous.min(expiry)),
            );
        }
        Ok(earliest_expiry)
    }

    fn completed_observation(
        &self,
        attempt: &AttemptRecord,
    ) -> Result<Observation, SupervisorError> {
        let history = self.reconciliation_history(&attempt.id)?;
        let (receipt, challenge, phase) = match history
            .iter()
            .rev()
            .find(|record| record.state == ReconciliationState::Completed)
        {
            Some(record) => (
                record.receipt.as_ref(),
                &record.challenge,
                EvidencePhase::Reconciliation,
            ),
            None => (
                attempt.receipt.as_ref(),
                &attempt.evidence_challenge,
                EvidencePhase::Execution,
            ),
        };
        let Some(OperationReceipt::Completed { observation }) = receipt else {
            return Err(denied("interlock observation has no successful receipt"));
        };
        let digest = observation
            .evidence
            .as_ref()
            .ok_or_else(|| denied("interlock observation lacks evidence"))?;
        let artifact = self
            .artifacts
            .verify_source(digest, &EvidenceSource::Attempt(attempt.id.clone()))
            .map_err(|error| denied(error.to_string()))?;
        let envelope: EvidenceEnvelope = serde_json::from_slice(artifact.as_bytes())
            .map_err(|error| denied(error.to_string()))?;
        let mut expected = observation.clone();
        expected.evidence = None;
        if envelope.attempt != attempt.id
            || &envelope.challenge != challenge
            || envelope.phase != phase
            || envelope.observation != expected
        {
            return Err(denied(
                "interlock evidence no longer binds its durable receipt",
            ));
        }
        Ok(observation.clone())
    }
}

fn denied(reason: impl Into<String>) -> SupervisorError {
    SupervisorError::OutOfBounds {
        reason: reason.into(),
    }
}
