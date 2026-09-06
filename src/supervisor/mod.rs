//! The single authority that admits durable physical effects and records their outcome.

mod interlocks;

use std::sync::Arc;

use snafu::Snafu;

use crate::domain::{
    ArtifactDigest, AttemptId, AttemptRecord, AttemptState, Budget, CaseFact, CaseId,
    CommissionedProfile, EvidenceEnvelope, EvidencePhase, Grant, GrantId,
    HaltedRunAbandonmentRecord, Operation, OperationReceipt, PlanId, PlanProposal, PlanRun,
    PlannedOperation, Principal, PrincipalRole, ReconciliationSetup, RecoveryTakeoverRecord,
    RequestId, ReviewedPlan,
};
use crate::evidence::{ArtifactStore, EvidenceError, VerifiedArtifact};
use crate::store::{
    AdmissionSnapshot, ReconciliationClaim, ReservationOutcome, SqliteStore, StoreError,
};

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum BackendError {
    #[snafu(display("backend returned malformed data: {message}"))]
    Malformed { message: String },

    #[snafu(display("backend timed out: {message}"))]
    Timeout { message: String },

    #[snafu(display("backend transport failed: {message}"))]
    Transport { message: String },
}

pub trait ArtifactResolver: Send + Sync {
    fn resolve(&self, digest: &ArtifactDigest) -> Result<VerifiedArtifact, EvidenceError>;
}

impl ArtifactResolver for ArtifactStore {
    fn resolve(&self, digest: &ArtifactDigest) -> Result<VerifiedArtifact, EvidenceError> {
        self.read(digest)
    }
}

#[derive(Debug, Clone)]
pub struct DispatchRequest {
    pub attempt: AttemptId,
    pub operation: Operation,
    pub deadline_milliseconds: u64,
    pub expected_target_fingerprint: ArtifactDigest,
    pub expected_instrument_fingerprints: Vec<(crate::domain::InstrumentId, ArtifactDigest)>,
    pub expected_instrument_configurations: Vec<(crate::domain::InstrumentId, ArtifactDigest)>,
    pub expected_instrument_physical_identities: Vec<(crate::domain::InstrumentId, ArtifactDigest)>,
    pub expected_fixture_revision: ArtifactDigest,
    pub evidence_challenge: ArtifactDigest,
    pub evidence_phase: EvidencePhase,
    pub configure_instrument: bool,
    pub interlocks_valid_until: Option<jiff::Timestamp>,
}

#[derive(Debug, Clone)]
pub struct ReconciliationRequest {
    pub attempt: AttemptId,
    pub dispatch: DispatchRequest,
}

pub trait Backend: Send + Sync {
    /// Validate a frozen adapter binding without touching a physical target.
    fn preflight(
        &self,
        operation: &Operation,
        profile: &CommissionedProfile,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError>;

    /// Re-observe target, instruments, and fixture before applying the requested operation.
    fn execute(
        &self,
        request: &DispatchRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError>;

    /// Produce fresh backend-derived evidence for a durable unknown attempt.
    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError>;
}

#[derive(Debug, Clone)]
pub struct SubmitRequest {
    pub attempt: AttemptId,
    pub request: RequestId,
    pub grant: GrantId,
    pub plan: PlanId,
    pub operation_index: usize,
}

#[derive(Debug, Clone)]
pub struct PlanAdmissionRequest {
    pub run: RequestId,
    pub first_attempt: AttemptId,
    pub grant: GrantId,
    pub plan: PlanId,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTakeoverRequest {
    pub request: RequestId,
    pub run: RequestId,
    pub first_attempt: AttemptId,
    pub unresolved: Vec<AttemptId>,
    pub grant: GrantId,
    pub plan: PlanId,
    pub justification_evidence: ArtifactDigest,
}

/// Operator-only request to close a run that halted before any unresolved
/// physical outcome.  The store derives the exact owned lease set atomically.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HaltedRunAbandonmentRequest {
    pub request: RequestId,
    pub run: RequestId,
    pub grant: GrantId,
    pub plan: PlanId,
    pub justification_evidence: ArtifactDigest,
}

#[derive(Debug, Clone)]
pub struct DispatchTicket {
    attempt: AttemptId,
}

#[derive(Debug, Clone)]
pub struct PlanTicket {
    run: RequestId,
    grant: GrantId,
    plan: PlanId,
    dispatch: DispatchTicket,
    operation_index: usize,
}

#[derive(Debug, Clone)]
pub struct PlanProgress {
    pub attempt: AttemptRecord,
    pub next: Option<PlanTicket>,
}

#[derive(Debug, Clone)]
pub enum Submission {
    Existing(Box<AttemptRecord>),
    Admitted(DispatchTicket),
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SupervisorError {
    #[snafu(display("persistence failed: {source}"))]
    Store { source: StoreError },

    #[snafu(display("backend failed: {source}"))]
    Backend { source: BackendError },

    #[snafu(display("principal {id} is not authorized as {required}"))]
    Role { id: String, required: &'static str },

    #[snafu(display("grant does not belong to this agent"))]
    GrantPrincipal,

    #[snafu(display("plan is not independently reviewed"))]
    UnreviewedPlan,

    #[snafu(display("plan no longer matches the commissioned fixture"))]
    ChangedFixture,

    #[snafu(display("operation is outside the current authority bounds: {reason}"))]
    OutOfBounds { reason: String },

    #[snafu(display("attempt is not in unknown state"))]
    NotUnknown,
}

#[derive(Clone)]
pub struct Supervisor {
    store: Arc<SqliteStore>,
    artifacts: Arc<ArtifactStore>,
}

impl Supervisor {
    pub fn new(store: Arc<SqliteStore>, artifacts: Arc<ArtifactStore>) -> Self {
        Self { store, artifacts }
    }

    pub fn commission(
        &self,
        authority: &Principal,
        profile: CommissionedProfile,
    ) -> Result<(), SupervisorError> {
        require_authority(authority)?;
        self.store
            .save_profile(&profile)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn issue_grant(
        &self,
        authority: &Principal,
        agent: &Principal,
        grant: Grant,
    ) -> Result<(), SupervisorError> {
        require_authority(authority)?;
        if agent.role != PrincipalRole::Agent
            || grant.agent != agent.id
            || grant.issued_by != authority.id
        {
            return Err(SupervisorError::GrantPrincipal);
        }
        let profile = self
            .store
            .profile(grant.profile.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "profile",
                    id: grant.profile.to_string(),
                },
            })?;
        if profile.target != grant.target {
            return Err(SupervisorError::OutOfBounds {
                reason: "grant target differs from profile".to_owned(),
            });
        }
        self.store
            .save_grant(&grant)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn revoke_grant(&self, authority: &Principal, id: &GrantId) -> Result<(), SupervisorError> {
        require_authority(authority)?;
        self.store
            .revoke_grant(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn propose_plan(
        &self,
        agent: &Principal,
        proposal: PlanProposal,
    ) -> Result<PlanProposal, SupervisorError> {
        require_agent(agent)?;
        if proposal.requested_by != agent.id || proposal.operations.is_empty() {
            return Err(SupervisorError::UnreviewedPlan);
        }
        self.store
            .save_proposal(&proposal)
            .map_err(|source| SupervisorError::Store { source })?;
        Ok(proposal)
    }

    pub fn review_proposal(
        &self,
        reviewer: &Principal,
        id: &PlanId,
        expected_digest: &ArtifactDigest,
    ) -> Result<ReviewedPlan, SupervisorError> {
        let proposal = self
            .store
            .proposal(id.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "proposal",
                    id: id.to_string(),
                },
            })?;
        if reviewer.role != PrincipalRole::Reviewer || reviewer.id == proposal.requested_by {
            return Err(SupervisorError::UnreviewedPlan);
        }
        if proposal.digest().map_err(|source| SupervisorError::Store {
            source: StoreError::Json { source },
        })? != *expected_digest
        {
            return Err(SupervisorError::Store {
                source: StoreError::ReviewDigestMismatch { id: id.clone() },
            });
        }
        let mut plan = ReviewedPlan {
            id: proposal.id,
            candidate_digest: proposal.candidate_digest,
            fixture_revision: proposal.fixture_revision,
            tool_digest: proposal.tool_digest,
            target_fingerprint: proposal.target_fingerprint,
            instrument_fingerprints: proposal.instrument_fingerprints,
            instrument_configuration_digests: proposal.instrument_configuration_digests,
            preconditions: proposal.preconditions,
            operations: proposal.operations,
            requested_by: proposal.requested_by,
            reviewed_by: reviewer.id.clone(),
            review_digest: ArtifactDigest::sha256(b"pending-review"),
            reconciliation_setup: proposal.reconciliation_setup,
        };
        plan.review_digest = plan.digest().map_err(|source| SupervisorError::Store {
            source: StoreError::Json { source },
        })?;
        self.store
            .consume_reviewed_proposal(id, expected_digest, &plan)
            .map_err(|source| SupervisorError::Store { source })?;
        Ok(plan)
    }

    pub fn append_case_fact(&self, case: &CaseId, fact: &CaseFact) -> Result<(), SupervisorError> {
        self.store
            .append_case_fact(case, fact)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn case(&self, id: &CaseId) -> Result<crate::domain::CaseRecord, SupervisorError> {
        self.store
            .case(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn profile(&self, id: &str) -> Result<Option<CommissionedProfile>, SupervisorError> {
        self.store
            .profile(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn grant(&self, id: &str) -> Result<Option<Grant>, SupervisorError> {
        self.store
            .grant(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn plan(&self, id: &str) -> Result<Option<ReviewedPlan>, SupervisorError> {
        self.store
            .plan(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn attempt(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, SupervisorError> {
        self.store
            .attempt(id)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn reconciliation_history(
        &self,
        attempt: &AttemptId,
    ) -> Result<Vec<crate::domain::ReconciliationRecord>, SupervisorError> {
        self.store
            .reconciliation_history(attempt)
            .map_err(|source| SupervisorError::Store { source })
    }

    pub fn submit(
        &self,
        agent: &Principal,
        request: SubmitRequest,
    ) -> Result<Submission, SupervisorError> {
        require_agent(agent)?;
        let grant = self
            .store
            .grant(request.grant.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "grant",
                    id: request.grant.to_string(),
                },
            })?;
        if grant.agent != agent.id {
            return Err(SupervisorError::GrantPrincipal);
        }
        let profile = self
            .store
            .profile(grant.profile.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "profile",
                    id: grant.profile.to_string(),
                },
            })?;
        let plan = self
            .store
            .plan(request.plan.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "plan",
                    id: request.plan.to_string(),
                },
            })?;
        let operation = plan
            .operations
            .get(request.operation_index)
            .ok_or_else(|| SupervisorError::OutOfBounds {
                reason: "operation index is absent".to_owned(),
            })?;
        authorize(&grant, &profile, &plan, operation)?;
        let digest = plan.digest().map_err(|source| SupervisorError::Store {
            source: StoreError::Json { source },
        })?;
        let reserved = if request.operation_index == 0 {
            plan.operations
                .iter()
                .try_fold(Budget::ZERO, |total, operation| {
                    total.checked_add(&operation.worst_case_budget())
                })
                .ok_or_else(|| SupervisorError::OutOfBounds {
                    reason: "plan budget overflow".to_owned(),
                })?
        } else {
            Budget::ZERO
        };
        let now = jiff::Timestamp::now().to_string();
        let evidence_challenge =
            ArtifactDigest::sha256(format!("{}:{}:0", request.attempt, now).as_bytes());
        let proposed = AttemptRecord {
            id: request.attempt,
            request: request.request,
            grant: request.grant,
            plan: request.plan,
            operation_index: request.operation_index,
            plan_digest: digest,
            reserved,
            profile: profile.id.clone(),
            profile_digest: profile.digest().map_err(|source| SupervisorError::Store {
                source: StoreError::Json { source },
            })?,
            leased_resources: profile.physical_resources(),
            evidence_challenge,
            evidence_ordinal: 0,
            state: AttemptState::Intent,
            receipt: None,
            created_at: now.clone(),
            updated_at: now,
        };
        match self
            .store
            .reserve(
                &proposed,
                &AdmissionSnapshot {
                    agent: agent.id.clone(),
                    profile,
                    plan,
                },
            )
            .map_err(|source| SupervisorError::Store { source })?
        {
            ReservationOutcome::Existing(attempt) => Ok(Submission::Existing(Box::new(attempt))),
            ReservationOutcome::Reserved(_) => Ok(Submission::Admitted(DispatchTicket {
                attempt: proposed.id,
            })),
        }
    }

    pub fn admit_plan(
        &self,
        agent: &Principal,
        request: PlanAdmissionRequest,
        backend: &dyn Backend,
    ) -> Result<PlanTicket, SupervisorError> {
        require_agent(agent)?;
        let grant = self
            .grant(request.grant.as_str())?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "grant",
                    id: request.grant.to_string(),
                },
            })?;
        if grant.agent != agent.id {
            return Err(SupervisorError::GrantPrincipal);
        }
        if self
            .store
            .is_halted_pair(&request.grant, &request.plan)
            .map_err(|source| SupervisorError::Store { source })?
            || self
                .store
                .is_recovery_source_retired(&request.grant, &request.plan)
                .map_err(|source| SupervisorError::Store { source })?
        {
            return Err(SupervisorError::OutOfBounds {
                reason: "plan authority was closed by a halted-run abandonment".to_owned(),
            });
        }
        let profile =
            self.profile(grant.profile.as_str())?
                .ok_or_else(|| SupervisorError::Store {
                    source: StoreError::Missing {
                        kind: "profile",
                        id: grant.profile.to_string(),
                    },
                })?;
        let plan = self
            .plan(request.plan.as_str())?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "plan",
                    id: request.plan.to_string(),
                },
            })?;
        self.preflight_plan(&grant, &profile, &plan, backend)?;
        let steps = self.plan_steps(
            &request.run,
            &request.first_attempt,
            &request.run,
            plan.operations.len(),
        )?;
        self.store
            .create_run(&PlanRun {
                id: request.run.clone(),
                agent: agent.id.clone(),
                grant: request.grant.clone(),
                plan: request.plan.clone(),
                steps,
                cursor: 0,
            })
            .map_err(|source| SupervisorError::Store { source })?;
        let submission = self.submit(
            agent,
            SubmitRequest {
                attempt: request.first_attempt,
                request: request.run.clone(),
                grant: request.grant.clone(),
                plan: request.plan.clone(),
                operation_index: 0,
            },
        )?;
        match submission {
            Submission::Admitted(dispatch) => Ok(PlanTicket {
                run: request.run,
                grant: request.grant,
                plan: request.plan,
                dispatch,
                operation_index: 0,
            }),
            Submission::Existing(existing) if existing.state == AttemptState::Intent => {
                Ok(PlanTicket {
                    run: request.run,
                    grant: request.grant,
                    plan: request.plan,
                    dispatch: DispatchTicket {
                        attempt: existing.id.clone(),
                    },
                    operation_index: 0,
                })
            }
            Submission::Existing(_) => Err(SupervisorError::OutOfBounds {
                reason: "run already has a non-resumable first step".to_owned(),
            }),
        }
    }

    /// Transfers an unresolved physical lease into an independently reviewed
    /// recovery run.  This never edits or resolves the source attempts.
    pub fn takeover_recovery(
        &self,
        authority: &Principal,
        request: RecoveryTakeoverRequest,
        backend: &dyn Backend,
    ) -> Result<PlanTicket, SupervisorError> {
        require_authority(authority)?;
        if request.unresolved.is_empty() {
            return Err(SupervisorError::OutOfBounds {
                reason: "recovery must name an unresolved attempt".to_owned(),
            });
        }
        self.artifacts
            .resolve(&request.justification_evidence)
            .map_err(|source| SupervisorError::OutOfBounds {
                reason: source.to_string(),
            })?;
        let grant = self
            .grant(request.grant.as_str())?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "grant",
                    id: request.grant.to_string(),
                },
            })?;
        let profile =
            self.profile(grant.profile.as_str())?
                .ok_or_else(|| SupervisorError::Store {
                    source: StoreError::Missing {
                        kind: "profile",
                        id: grant.profile.to_string(),
                    },
                })?;
        let plan = self
            .plan(request.plan.as_str())?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "plan",
                    id: request.plan.to_string(),
                },
            })?;
        self.preflight_plan(&grant, &profile, &plan, backend)?;
        let steps = self.plan_steps(
            &request.run,
            &request.first_attempt,
            &request.request,
            plan.operations.len(),
        )?;
        let now = jiff::Timestamp::now().to_string();
        let proposed = AttemptRecord {
            id: request.first_attempt.clone(),
            request: request.request.clone(),
            grant: request.grant.clone(),
            plan: request.plan.clone(),
            operation_index: 0,
            plan_digest: plan.digest().map_err(|source| SupervisorError::Store {
                source: StoreError::Json { source },
            })?,
            reserved: plan
                .operations
                .iter()
                .try_fold(Budget::ZERO, |total, operation| {
                    total.checked_add(&operation.worst_case_budget())
                })
                .ok_or_else(|| SupervisorError::OutOfBounds {
                    reason: "plan budget overflow".to_owned(),
                })?,
            profile: profile.id.clone(),
            profile_digest: profile.digest().map_err(|source| SupervisorError::Store {
                source: StoreError::Json { source },
            })?,
            leased_resources: profile.physical_resources(),
            evidence_challenge: ArtifactDigest::sha256(
                format!("{}:{}:0", request.first_attempt, now).as_bytes(),
            ),
            evidence_ordinal: 0,
            state: AttemptState::Intent,
            receipt: None,
            created_at: now.clone(),
            updated_at: now,
        };
        let record = RecoveryTakeoverRecord {
            request: request.request.clone(),
            run: request.run.clone(),
            first_attempt: request.first_attempt.clone(),
            unresolved: request.unresolved,
            grant: request.grant.clone(),
            plan: request.plan.clone(),
            resources: proposed.leased_resources.clone(),
            justification_evidence: request.justification_evidence,
            authorized_by: authority.id.clone(),
            authorized_at: jiff::Timestamp::now().to_string(),
        };
        match self
            .store
            .takeover_recovery(
                &proposed,
                &AdmissionSnapshot {
                    agent: grant.agent.clone(),
                    profile,
                    plan,
                },
                &PlanRun {
                    id: request.run.clone(),
                    agent: grant.agent,
                    grant: request.grant.clone(),
                    plan: request.plan.clone(),
                    steps,
                    cursor: 0,
                },
                &record,
            )
            .map_err(|source| SupervisorError::Store { source })?
        {
            ReservationOutcome::Existing(attempt)
            | ReservationOutcome::Reserved(crate::store::Reservation { attempt }) => {
                Ok(PlanTicket {
                    run: request.run,
                    grant: request.grant,
                    plan: request.plan,
                    dispatch: DispatchTicket {
                        attempt: attempt.id,
                    },
                    operation_index: 0,
                })
            }
        }
    }

    /// Close a halted run whose complete grant/plan history has no unresolved
    /// physical outcome. This is deliberately authority-only and never
    /// refunds the durable whole-plan reservation.
    pub fn abandon_halted_run(
        &self,
        authority: &Principal,
        request: HaltedRunAbandonmentRequest,
    ) -> Result<HaltedRunAbandonmentRecord, SupervisorError> {
        require_authority(authority)?;
        self.artifacts
            .resolve(&request.justification_evidence)
            .map_err(|source| SupervisorError::OutOfBounds {
                reason: source.to_string(),
            })?;
        let run = self
            .store
            .run(&request.run)
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "run",
                    id: request.run.to_string(),
                },
            })?;
        if run.grant != request.grant || run.plan != request.plan {
            return Err(SupervisorError::OutOfBounds {
                reason: "abandonment identity differs from the durable run".to_owned(),
            });
        }
        let resources = match self
            .store
            .halted_run_abandonment_request(&request.request)
            .map_err(|source| SupervisorError::Store { source })?
        {
            Some(existing) => existing.resources,
            None => self
                .store
                .halted_pair_resources(&request.grant, &request.plan)
                .map_err(|source| SupervisorError::Store { source })?,
        };
        self.store
            .abandon_halted_run(&HaltedRunAbandonmentRecord {
                request: request.request,
                run: request.run,
                grant: request.grant,
                plan: request.plan,
                resources,
                justification_evidence: request.justification_evidence,
                authorized_by: authority.id.clone(),
                authorized_at: jiff::Timestamp::now().to_string(),
            })
            .map_err(|source| SupervisorError::Store { source })
    }

    fn plan_steps(
        &self,
        run: &RequestId,
        first_attempt: &AttemptId,
        first_request: &RequestId,
        operation_count: usize,
    ) -> Result<Vec<(AttemptId, RequestId)>, SupervisorError> {
        let mut steps = Vec::with_capacity(operation_count);
        steps.push((first_attempt.clone(), first_request.clone()));
        for index in 1..operation_count {
            let token =
                ArtifactDigest::sha256(format!("plan-step:{}:{index}", run.as_str()).as_bytes());
            let attempt = AttemptId::try_from(format!("a{}", token.as_str())).map_err(|_| {
                SupervisorError::OutOfBounds {
                    reason: "cannot derive plan step id".to_owned(),
                }
            })?;
            let step_request =
                RequestId::try_from(format!("r{}", token.as_str())).map_err(|_| {
                    SupervisorError::OutOfBounds {
                        reason: "cannot derive plan request id".to_owned(),
                    }
                })?;
            steps.push((attempt, step_request));
        }
        Ok(steps)
    }

    fn preflight_plan(
        &self,
        grant: &Grant,
        profile: &CommissionedProfile,
        plan: &ReviewedPlan,
        backend: &dyn Backend,
    ) -> Result<(), SupervisorError> {
        interlocks::validate_plan(profile, plan)?;
        for digest in std::iter::once(&plan.candidate_digest)
            .chain(std::iter::once(&plan.tool_digest))
            .chain(plan.preconditions.iter())
        {
            self.artifacts
                .resolve(digest)
                .map_err(|source| SupervisorError::OutOfBounds {
                    reason: source.to_string(),
                })?;
        }
        for planned in &plan.operations {
            authorize(grant, profile, plan, planned)?;
            if let Operation::FlashWrite { source, .. } | Operation::FlashVerify { source, .. } =
                &planned.operation
            {
                self.artifacts
                    .resolve(source)
                    .map_err(|source| SupervisorError::OutOfBounds {
                        reason: source.to_string(),
                    })?;
            }
            backend
                .preflight(&planned.operation, profile, self.artifacts.as_ref())
                .map_err(|source| SupervisorError::Backend { source })?;
        }
        Ok(())
    }

    pub fn execute_next(
        &self,
        agent: &Principal,
        ticket: PlanTicket,
        backend: &dyn Backend,
    ) -> Result<PlanProgress, SupervisorError> {
        let attempt = self.execute(agent, ticket.dispatch.clone(), backend)?;
        if attempt.state != AttemptState::Completed {
            return Ok(PlanProgress {
                attempt,
                next: None,
            });
        }
        self.store
            .advance_run(&ticket.run, ticket.operation_index)
            .map_err(|source| SupervisorError::Store { source })?;
        let run = self
            .store
            .run(&ticket.run)
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "run",
                    id: ticket.run.to_string(),
                },
            })?;
        let next_index = ticket.operation_index + 1;
        if next_index == run.steps.len() {
            return Ok(PlanProgress {
                attempt,
                next: None,
            });
        }
        let (next_attempt, next_request) =
            run.steps
                .get(next_index)
                .cloned()
                .ok_or_else(|| SupervisorError::OutOfBounds {
                    reason: "run lacks next step identity".to_owned(),
                })?;
        let next = match self.submit(
            agent,
            SubmitRequest {
                attempt: next_attempt,
                request: next_request,
                grant: ticket.grant.clone(),
                plan: ticket.plan.clone(),
                operation_index: next_index,
            },
        )? {
            Submission::Admitted(dispatch) => PlanTicket {
                run: ticket.run,
                grant: ticket.grant,
                plan: ticket.plan,
                dispatch,
                operation_index: next_index,
            },
            Submission::Existing(existing) if existing.state == AttemptState::Intent => {
                PlanTicket {
                    run: ticket.run,
                    grant: ticket.grant,
                    plan: ticket.plan,
                    dispatch: DispatchTicket {
                        attempt: existing.id.clone(),
                    },
                    operation_index: next_index,
                }
            }
            Submission::Existing(_) => {
                return Err(SupervisorError::OutOfBounds {
                    reason: "next plan step is non-resumable".to_owned(),
                });
            }
        };
        Ok(PlanProgress {
            attempt,
            next: Some(next),
        })
    }

    pub fn execute(
        &self,
        agent: &Principal,
        ticket: DispatchTicket,
        backend: &dyn Backend,
    ) -> Result<AttemptRecord, SupervisorError> {
        require_agent(agent)?;
        let claimed = match self.store.claim_dispatch(&ticket.attempt, &agent.id) {
            Ok(value) => value,
            Err(source) => return Err(SupervisorError::Store { source }),
        };
        let preflight = if claimed.attempt.operation_index == 0 {
            self.preflight_plan(&claimed.grant, &claimed.profile, &claimed.plan, backend)
        } else {
            Ok(())
        };
        let dispatch = preflight.and_then(|()| {
            self.dispatch_from_snapshot(
                &claimed.attempt,
                &claimed.grant,
                &claimed.profile,
                &claimed.plan,
                EvidencePhase::Execution,
            )
        });
        let dispatch = match dispatch.and_then(|mut dispatch| {
            dispatch.interlocks_valid_until =
                self.check_live_interlocks(&claimed.attempt, &claimed.profile, &claimed.plan)?;
            Ok(dispatch)
        }) {
            Ok(dispatch) => dispatch,
            Err(error) => {
                return self
                    .store
                    .record_receipt(
                        &claimed.attempt.id,
                        OperationReceipt::Rejected {
                            reason: error.to_string(),
                        },
                        true,
                    )
                    .map_err(|source| SupervisorError::Store { source });
            }
        };
        let receipt = backend
            .execute(&dispatch, self.artifacts.as_ref())
            .unwrap_or_else(|error| OperationReceipt::Unknown {
                reason: error.to_string(),
                observation: None,
            });
        let receipt = self
            .verify_receipt_evidence(&claimed.attempt, &dispatch, receipt)
            .unwrap_or_else(|error| OperationReceipt::Unknown {
                reason: error.to_string(),
                observation: None,
            });
        let receipt = interlocks::check_postconditions(
            &claimed.plan.operations[claimed.attempt.operation_index],
            receipt,
        );
        let release_lease = matches!(receipt, OperationReceipt::Rejected { .. })
            || (matches!(receipt, OperationReceipt::Completed { .. })
                && claimed.attempt.operation_index + 1 == claimed.plan.operations.len());
        let recorded = self
            .store
            .record_receipt(&claimed.attempt.id, receipt, release_lease)
            .map_err(|source| SupervisorError::Store { source })?;
        Ok(recorded)
    }

    pub fn resume_plan(
        &self,
        agent: &Principal,
        run_id: &RequestId,
    ) -> Result<PlanTicket, SupervisorError> {
        require_agent(agent)?;
        let run = self
            .store
            .repair_run_cursor(run_id)
            .map_err(|source| SupervisorError::Store { source })?;
        if run.agent != agent.id {
            return Err(SupervisorError::GrantPrincipal);
        }
        if self
            .store
            .halted_run_abandonment(&run.id)
            .map_err(|source| SupervisorError::Store { source })?
            .is_some()
            || self
                .store
                .is_recovery_source_retired(&run.grant, &run.plan)
                .map_err(|source| SupervisorError::Store { source })?
        {
            return Err(SupervisorError::OutOfBounds {
                reason: "plan run was closed by a halted-run abandonment".to_owned(),
            });
        }
        for (index, (attempt_id, request_id)) in run.steps.iter().enumerate() {
            match self.attempt(attempt_id)? {
                Some(attempt) if attempt.state == AttemptState::Completed => continue,
                Some(attempt) if attempt.state == AttemptState::Intent => {
                    return Ok(PlanTicket {
                        run: run.id,
                        grant: run.grant,
                        plan: run.plan,
                        dispatch: DispatchTicket {
                            attempt: attempt.id,
                        },
                        operation_index: index,
                    });
                }
                Some(_) => {
                    return Err(SupervisorError::OutOfBounds {
                        reason: "plan is held by an unresolved step".to_owned(),
                    });
                }
                None => {
                    let submission = self.submit(
                        agent,
                        SubmitRequest {
                            attempt: attempt_id.clone(),
                            request: request_id.clone(),
                            grant: run.grant.clone(),
                            plan: run.plan.clone(),
                            operation_index: index,
                        },
                    )?;
                    let dispatch = match submission {
                        Submission::Admitted(ticket) => ticket,
                        Submission::Existing(existing)
                            if existing.state == AttemptState::Intent =>
                        {
                            DispatchTicket {
                                attempt: existing.id.clone(),
                            }
                        }
                        Submission::Existing(_) => {
                            return Err(SupervisorError::OutOfBounds {
                                reason: "durable run step is non-resumable".to_owned(),
                            });
                        }
                    };
                    return Ok(PlanTicket {
                        run: run.id,
                        grant: run.grant,
                        plan: run.plan,
                        dispatch,
                        operation_index: index,
                    });
                }
            }
        }
        Err(SupervisorError::OutOfBounds {
            reason: "plan run is complete".to_owned(),
        })
    }

    pub fn resume(
        &self,
        agent: &Principal,
        request: &RequestId,
        backend: &dyn Backend,
    ) -> Result<AttemptRecord, SupervisorError> {
        require_agent(agent)?;
        let attempt = self
            .store
            .attempt_for_request(request)
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "request",
                    id: request.to_string(),
                },
            })?;
        if attempt.state != AttemptState::Intent {
            return Err(SupervisorError::OutOfBounds {
                reason: "only an undispatched durable intent can resume".to_owned(),
            });
        }
        self.execute(
            agent,
            DispatchTicket {
                attempt: attempt.id,
            },
            backend,
        )
    }

    pub fn execute_plan(
        &self,
        agent: &Principal,
        requests: Vec<SubmitRequest>,
        backend: &dyn Backend,
    ) -> Result<Vec<AttemptRecord>, SupervisorError> {
        let mut attempts = Vec::with_capacity(requests.len());
        for request in requests {
            match self.submit(agent, request)? {
                Submission::Admitted(ticket) => {
                    let attempt = self.execute(agent, ticket, backend)?;
                    if attempt.state != AttemptState::Completed {
                        attempts.push(attempt);
                        break;
                    }
                    attempts.push(attempt);
                }
                Submission::Existing(attempt) if attempt.state == AttemptState::Completed => {
                    attempts.push(*attempt)
                }
                Submission::Existing(_) => {
                    return Err(SupervisorError::OutOfBounds {
                        reason: "plan has a durable non-completed step".to_owned(),
                    });
                }
            }
        }
        Ok(attempts)
    }

    pub fn reconcile(
        &self,
        principal: &Principal,
        attempt_id: &AttemptId,
        request_id: &RequestId,
        backend: &dyn Backend,
    ) -> Result<AttemptRecord, SupervisorError> {
        require_agent(principal)?;
        let attempt = self
            .store
            .attempt(attempt_id)
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "attempt",
                    id: attempt_id.to_string(),
                },
            })?;
        let grant = self
            .store
            .grant(attempt.grant.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "grant",
                    id: attempt.grant.to_string(),
                },
            })?;
        if principal.id != grant.agent {
            return Err(SupervisorError::GrantPrincipal);
        }
        if !matches!(attempt.state, AttemptState::Unknown | AttemptState::Partial) {
            if self
                .store
                .reconciliation_history(attempt_id)
                .map_err(|source| SupervisorError::Store { source })?
                .iter()
                .any(|record| record.request == *request_id)
            {
                return Ok(attempt);
            }
            return Err(SupervisorError::NotUnknown);
        }
        let plan = self
            .store
            .plan(attempt.plan.as_str())
            .map_err(|source| SupervisorError::Store { source })?
            .ok_or_else(|| SupervisorError::Store {
                source: StoreError::Missing {
                    kind: "plan",
                    id: attempt.plan.to_string(),
                },
            })?;
        let operation = plan
            .operations
            .get(attempt.operation_index)
            .ok_or_else(|| SupervisorError::OutOfBounds {
                reason: "operation index is absent".to_owned(),
            })?;
        let configure = matches!(
            plan.reconciliation_setup,
            ReconciliationSetup::ApplyReviewedInstrumentConfiguration
        );
        let configuration_budget = if configure {
            Some(Budget {
                effects: 1,
                bytes: 0,
                milliseconds: operation.max_milliseconds,
            })
        } else {
            None
        };
        let claimed = match self
            .store
            .claim_reconciliation(
                attempt_id,
                request_id,
                &principal.id,
                configuration_budget.as_ref(),
            )
            .map_err(|source| SupervisorError::Store { source })?
        {
            ReconciliationClaim::Existing(_) => {
                return self
                    .attempt(attempt_id)?
                    .ok_or_else(|| SupervisorError::Store {
                        source: StoreError::Missing {
                            kind: "attempt",
                            id: attempt_id.to_string(),
                        },
                    });
            }
            ReconciliationClaim::Claimed(claimed) => claimed,
        };
        let dispatch = self.dispatch_for_reconciliation(
            &claimed.dispatch.attempt,
            &claimed.dispatch.profile,
            &claimed.dispatch.plan,
            claimed.record.challenge.clone(),
            configure,
        ).and_then(|dispatch| {
            if configure && claimed.dispatch.profile.live_interlocks.iter().any(|interlock| {
                interlock.effects().contains(&crate::domain::EffectPermission::InstrumentConfigure)
            }) {
                return Err(SupervisorError::OutOfBounds {
                    reason: "interlocked configuration requires a reviewed recovery plan with a fresh observation after the uncertain effect".to_owned(),
                });
            }
            Ok(dispatch)
        });
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(error) => {
                self.store
                    .finish_reconciliation(request_id, None, false, false)
                    .map_err(|source| SupervisorError::Store { source })?;
                return Err(error);
            }
        };
        let receipt = match backend.reconcile(
            &ReconciliationRequest {
                attempt: attempt.id.clone(),
                dispatch: dispatch.clone(),
            },
            self.artifacts.as_ref(),
        ) {
            Ok(receipt) => receipt,
            Err(source) => {
                self.store
                    .finish_reconciliation(request_id, None, false, false)
                    .map_err(|source| SupervisorError::Store { source })?;
                return Err(SupervisorError::Backend { source });
            }
        };
        if matches!(
            receipt,
            OperationReceipt::Unknown {
                observation: None,
                ..
            } | OperationReceipt::Rejected { .. }
        ) {
            self.store
                .finish_reconciliation(request_id, None, false, false)
                .map_err(|source| SupervisorError::Store { source })?;
            return Err(SupervisorError::OutOfBounds {
                reason: "reconciliation outcome lacks fresh evidence".to_owned(),
            });
        }
        let receipt =
            match self.verify_receipt_evidence(&claimed.dispatch.attempt, &dispatch, receipt) {
                Ok(receipt) => receipt,
                Err(error) => {
                    self.store
                        .finish_reconciliation(request_id, None, false, false)
                        .map_err(|source| SupervisorError::Store { source })?;
                    return Err(error);
                }
            };
        let receipt = interlocks::check_postconditions(operation, receipt);
        let release_lease = matches!(receipt, OperationReceipt::Completed { .. })
            && claimed.dispatch.attempt.operation_index + 1
                == claimed.dispatch.plan.operations.len();
        let recorded = self
            .store
            .finish_reconciliation(
                request_id,
                Some(receipt.clone()),
                matches!(receipt, OperationReceipt::Completed { .. }),
                release_lease,
            )
            .map_err(|source| SupervisorError::Store { source })?;
        Ok(recorded)
    }

    fn dispatch_for_reconciliation(
        &self,
        attempt: &AttemptRecord,
        profile: &CommissionedProfile,
        plan: &ReviewedPlan,
        challenge: ArtifactDigest,
        configure_instrument: bool,
    ) -> Result<DispatchRequest, SupervisorError> {
        let operation = plan
            .operations
            .get(attempt.operation_index)
            .ok_or_else(|| SupervisorError::OutOfBounds {
                reason: "operation index is absent".to_owned(),
            })?;
        let fingerprints = profile
            .instruments
            .iter()
            .map(|(id, binding)| (id.clone(), binding.fingerprint.clone()))
            .collect();
        let configurations = profile
            .instruments
            .iter()
            .map(|(id, binding)| (id.clone(), binding.configuration_digest.clone()))
            .collect();
        Ok(DispatchRequest {
            attempt: attempt.id.clone(),
            operation: operation.operation.clone(),
            deadline_milliseconds: operation.max_milliseconds,
            expected_target_fingerprint: profile.target_fingerprint.clone(),
            expected_instrument_fingerprints: fingerprints,
            expected_instrument_configurations: configurations,
            expected_instrument_physical_identities: profile
                .instruments
                .iter()
                .map(|(id, binding)| (id.clone(), binding.physical_identity.clone()))
                .collect(),
            expected_fixture_revision: profile.fixture_revision.clone(),
            evidence_challenge: challenge,
            evidence_phase: EvidencePhase::Reconciliation,
            configure_instrument,
            interlocks_valid_until: None,
        })
    }

    fn dispatch_from_snapshot(
        &self,
        attempt: &AttemptRecord,
        grant: &Grant,
        profile: &CommissionedProfile,
        plan: &ReviewedPlan,
        phase: EvidencePhase,
    ) -> Result<DispatchRequest, SupervisorError> {
        let operation = plan
            .operations
            .get(attempt.operation_index)
            .ok_or_else(|| SupervisorError::OutOfBounds {
                reason: "operation index is absent".to_owned(),
            })?;
        authorize(grant, profile, plan, operation)?;
        let fingerprints = profile
            .instruments
            .iter()
            .map(|(id, binding)| (id.clone(), binding.fingerprint.clone()))
            .collect();
        let configurations = profile
            .instruments
            .iter()
            .map(|(id, binding)| (id.clone(), binding.configuration_digest.clone()))
            .collect();
        Ok(DispatchRequest {
            attempt: attempt.id.clone(),
            operation: operation.operation.clone(),
            deadline_milliseconds: operation.max_milliseconds,
            expected_target_fingerprint: profile.target_fingerprint.clone(),
            expected_instrument_fingerprints: fingerprints,
            expected_instrument_configurations: configurations,
            expected_instrument_physical_identities: profile
                .instruments
                .iter()
                .map(|(id, binding)| (id.clone(), binding.physical_identity.clone()))
                .collect(),
            expected_fixture_revision: profile.fixture_revision.clone(),
            evidence_challenge: attempt.evidence_challenge.clone(),
            evidence_phase: phase,
            configure_instrument: true,
            interlocks_valid_until: None,
        })
    }

    fn verify_receipt_evidence(
        &self,
        attempt: &AttemptRecord,
        dispatch: &DispatchRequest,
        receipt: OperationReceipt,
    ) -> Result<OperationReceipt, SupervisorError> {
        let observation = match &receipt {
            OperationReceipt::Completed { observation }
            | OperationReceipt::Partial { observation, .. }
            | OperationReceipt::Unknown {
                observation: Some(observation),
                ..
            } => observation,
            OperationReceipt::Unknown {
                observation: None, ..
            }
            | OperationReceipt::Rejected { .. } => {
                return Ok(receipt);
            }
        };
        let digest = observation
            .evidence
            .as_ref()
            .ok_or_else(|| SupervisorError::OutOfBounds {
                reason: "accepted receipt lacks evidence".to_owned(),
            })?;
        let artifact = self
            .artifacts
            .verify_source(
                digest,
                &crate::evidence::EvidenceSource::Attempt(attempt.id.clone()),
            )
            .map_err(|source| SupervisorError::OutOfBounds {
                reason: source.to_string(),
            })?;
        let envelope: EvidenceEnvelope =
            serde_json::from_slice(artifact.as_bytes()).map_err(|source| {
                SupervisorError::OutOfBounds {
                    reason: source.to_string(),
                }
            })?;
        let mut expected_observation = observation.clone();
        expected_observation.evidence = None;
        if envelope.attempt != attempt.id
            || envelope.challenge != dispatch.evidence_challenge
            || envelope.phase != dispatch.evidence_phase
            || envelope.observation != expected_observation
        {
            return Err(SupervisorError::OutOfBounds {
                reason: "evidence envelope does not bind this receipt".to_owned(),
            });
        }
        Ok(receipt)
    }
}

fn require_authority(principal: &Principal) -> Result<(), SupervisorError> {
    if matches!(
        principal.role,
        PrincipalRole::Operator | PrincipalRole::Admin
    ) {
        Ok(())
    } else {
        Err(SupervisorError::Role {
            id: principal.id.to_string(),
            required: "operator or admin",
        })
    }
}

fn require_agent(principal: &Principal) -> Result<(), SupervisorError> {
    if principal.role == PrincipalRole::Agent {
        Ok(())
    } else {
        Err(SupervisorError::Role {
            id: principal.id.to_string(),
            required: "agent",
        })
    }
}

fn authorize(
    grant: &Grant,
    profile: &CommissionedProfile,
    plan: &ReviewedPlan,
    planned: &PlannedOperation,
) -> Result<(), SupervisorError> {
    if grant.revoked {
        return Err(SupervisorError::OutOfBounds {
            reason: "grant is revoked".to_owned(),
        });
    }
    if plan.reviewed_by == plan.requested_by
        || plan.review_digest
            != plan.digest().map_err(|source| SupervisorError::Store {
                source: StoreError::Json { source },
            })?
    {
        return Err(SupervisorError::UnreviewedPlan);
    }
    if plan.fixture_revision != profile.fixture_revision
        || plan.target_fingerprint != profile.target_fingerprint
    {
        return Err(SupervisorError::ChangedFixture);
    }
    if plan.instrument_fingerprints.len() != profile.instruments.len()
        || plan.instrument_fingerprints.iter().any(|(id, digest)| {
            profile
                .instrument(id)
                .is_none_or(|binding| &binding.fingerprint != digest)
        })
    {
        return Err(SupervisorError::ChangedFixture);
    }
    let operation = &planned.operation;
    if operation.target() != &grant.target || operation.target() != &profile.target {
        return Err(SupervisorError::OutOfBounds {
            reason: "target differs from grant or profile".to_owned(),
        });
    }
    if !grant.capabilities.contains(&operation.capability())
        || !profile
            .permitted_capabilities
            .contains(&operation.capability())
    {
        return Err(SupervisorError::OutOfBounds {
            reason: "capability is not permitted".to_owned(),
        });
    }
    if !operation
        .effect_permissions()
        .is_subset(&grant.effect_permissions)
    {
        return Err(SupervisorError::OutOfBounds {
            reason: "effect permission is absent".to_owned(),
        });
    }
    if let Some(instrument) = operation.instrument() {
        let binding = profile
            .instrument(instrument)
            .ok_or_else(|| SupervisorError::ChangedFixture)?;
        if !binding
            .qualified_capabilities
            .contains(&operation.capability())
            || !operation
                .effect_permissions()
                .is_subset(&binding.qualified_effect_permissions)
            || plan.instrument_fingerprints.get(instrument) != Some(&binding.fingerprint)
            || plan.instrument_configuration_digests.get(instrument)
                != Some(&binding.configuration_digest)
        {
            return Err(SupervisorError::ChangedFixture);
        }
    }
    match operation {
        Operation::Wait { milliseconds, .. }
            if *milliseconds == 0 || *milliseconds > planned.max_milliseconds =>
        {
            Err(SupervisorError::OutOfBounds {
                reason: "wait must fit its positive operation deadline".to_owned(),
            })
        }
        Operation::PsuSet {
            millivolts,
            milliamps,
            ..
        } if *millivolts > profile.electrical_limits.max_millivolts
            || *milliamps > profile.electrical_limits.max_milliamps =>
        {
            Err(SupervisorError::OutOfBounds {
                reason: "power limits exceeded".to_owned(),
            })
        }
        Operation::FlashRead { offset, length, .. }
        | Operation::FlashErase { offset, length, .. }
        | Operation::FlashWrite { offset, length, .. }
        | Operation::FlashVerify { offset, length, .. }
            if !profile.region_limits.contains(*offset, *length) =>
        {
            Err(SupervisorError::OutOfBounds {
                reason: "flash region exceeded".to_owned(),
            })
        }
        _ if planned.max_milliseconds == 0 => Err(SupervisorError::OutOfBounds {
            reason: "operation deadline must be finite and non-zero".to_owned(),
        }),
        _ => Ok(()),
    }
}
