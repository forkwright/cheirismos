use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier, Mutex};

use cheirismos::conditions::{CheckTest, JsonPointer, LiveInterlock, ObservationCheck};
use cheirismos::domain::{
    ArtifactDigest, AttemptId, AttemptRecord, AttemptState, Budget, Capability,
    CommissionedProfile, EffectPermission, ElectricalLimits, EvidenceEnvelope, FixtureSessionId,
    Grant, GrantId, InstrumentBinding, InstrumentId, Observation, Operation, OperationReceipt,
    PlanId, PlanRun, PlannedOperation, Principal, PrincipalId, PrincipalRole, ProfileId,
    ReconciliationSetup, RegionLimits, RequestId, ReviewedPlan, TargetId,
};
use cheirismos::evidence::{ArtifactStore, EvidenceSource};
use cheirismos::store::{AdmissionSnapshot, SqliteStore};
use cheirismos::supervisor::{
    ArtifactResolver, Backend, BackendError, DispatchRequest, HaltedRunAbandonmentRequest,
    PlanAdmissionRequest, ReconciliationRequest, RecoveryTakeoverRequest, Submission,
    SubmitRequest, Supervisor,
};

fn id<T>(value: &'static str) -> Result<T, cheirismos::domain::DomainError>
where
    T: TryFrom<&'static str, Error = cheirismos::domain::DomainError>,
{
    value.try_into()
}

fn digest(value: &'static [u8]) -> ArtifactDigest {
    ArtifactDigest::sha256(value)
}

fn principal(
    value: &'static str,
    role: PrincipalRole,
) -> Result<Principal, cheirismos::domain::DomainError> {
    Ok(Principal {
        id: id(value)?,
        role,
        authentication_fingerprint: digest(value.as_bytes()),
    })
}

type TestContext = (
    Supervisor,
    Arc<SqliteStore>,
    Arc<ArtifactStore>,
    Principal,
    Principal,
    Principal,
);

fn profile() -> Result<CommissionedProfile, cheirismos::domain::DomainError> {
    let instrument = id::<InstrumentId>("spi-a")?;
    Ok(CommissionedProfile {
        id: id::<ProfileId>("profile-a")?,
        target: id::<TargetId>("target-a")?,
        target_fingerprint: digest(b"target"),
        instruments: BTreeMap::from([(
            instrument,
            InstrumentBinding {
                fingerprint: digest(b"instrument"),
                physical_identity: digest(b"physical-instrument"),
                configuration_digest: digest(b"config"),
                qualified_capabilities: BTreeSet::from([Capability::Spi]),
                qualified_effect_permissions: BTreeSet::from([
                    EffectPermission::InstrumentConfigure,
                    EffectPermission::RawBusTransfer,
                ]),
                qualification_evidence: digest(b"qualification"),
            },
        )]),
        fixture_revision: digest(b"fixture"),
        fixture_session: id::<FixtureSessionId>("fixture-session-a")?,
        permitted_capabilities: BTreeSet::from([Capability::Spi]),
        electrical_limits: ElectricalLimits {
            max_millivolts: 5000,
            max_milliamps: 1000,
        },
        region_limits: RegionLimits {
            flash_start: 0,
            flash_end_exclusive: 4096,
        },
        commissioning_evidence: digest(b"commissioning"),
        live_interlocks: Vec::new(),
    })
}

fn grant() -> Result<Grant, cheirismos::domain::DomainError> {
    Ok(Grant {
        id: id::<GrantId>("grant-a")?,
        issued_by: id::<PrincipalId>("operator-a")?,
        agent: id::<PrincipalId>("agent-a")?,
        target: id::<TargetId>("target-a")?,
        profile: id::<ProfileId>("profile-a")?,
        capabilities: BTreeSet::from([Capability::Spi]),
        effect_permissions: BTreeSet::from([
            EffectPermission::InstrumentConfigure,
            EffectPermission::RawBusTransfer,
        ]),
        remaining: Budget::try_new(10, 1_000, 10_000)?,
        expires_at: "2099-01-01T00:00:00Z".to_owned(),
        revoked: false,
    })
}

fn plan(target: &'static str) -> Result<ReviewedPlan, cheirismos::domain::DomainError> {
    Ok(ReviewedPlan {
        id: id::<PlanId>("plan-a")?,
        candidate_digest: digest(b"candidate"),
        fixture_revision: digest(b"fixture"),
        tool_digest: digest(b"tool"),
        target_fingerprint: digest(b"target"),
        instrument_fingerprints: BTreeMap::from([(
            id::<InstrumentId>("spi-a")?,
            digest(b"instrument"),
        )]),
        instrument_configuration_digests: BTreeMap::from([(
            id::<InstrumentId>("spi-a")?,
            digest(b"config"),
        )]),
        preconditions: vec![digest(b"precondition")],
        operations: vec![PlannedOperation {
            operation: Operation::SpiTransfer {
                target: id(target)?,
                instrument: id("spi-a")?,
                tx: vec![1],
                rx_bytes: 1,
            },
            max_milliseconds: 100,
            postconditions: Vec::new(),
        }],
        requested_by: id("agent-a")?,
        reviewed_by: id("placeholder")?,
        review_digest: digest(b"unreviewed"),
        reconciliation_setup: ReconciliationSetup::ObservationOnly,
    })
}

struct CountingBackend {
    calls: Mutex<u32>,
    store: Arc<ArtifactStore>,
}

struct PartialBackend {
    store: Arc<ArtifactStore>,
}

struct ReconcileBackend {
    store: Arc<ArtifactStore>,
    calls: Mutex<u32>,
    configure: Mutex<Vec<bool>>,
    complete: bool,
    evidence: bool,
}

struct ObservationBackend {
    store: Arc<ArtifactStore>,
    calls: Mutex<u32>,
    captured_at: String,
    body: serde_json::Value,
}

impl Backend for PartialBackend {
    fn preflight(
        &self,
        _operation: &Operation,
        _profile: &cheirismos::domain::CommissionedProfile,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &DispatchRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        let mut observation = cheirismos::domain::Observation {
            captured_at: "2099-01-01T00:00:00Z".to_owned(),
            source_fingerprint: digest(b"instrument"),
            body: serde_json::json!({"partial": true}),
            evidence: None,
        };
        let envelope = EvidenceEnvelope {
            attempt: request.attempt.clone(),
            challenge: request.evidence_challenge.clone(),
            phase: request.evidence_phase,
            observation: observation.clone(),
        };
        observation.evidence = Some(
            self.store
                .publish(
                    &serde_json::to_vec(&envelope).map_err(|error| BackendError::Malformed {
                        message: error.to_string(),
                    })?,
                    EvidenceSource::Attempt(request.attempt.clone()),
                )
                .map_err(|error| BackendError::Transport {
                    message: error.to_string(),
                })?,
        );
        Ok(cheirismos::domain::OperationReceipt::Partial {
            observation,
            reason: "transport ended after the first byte".to_owned(),
        })
    }

    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        self.execute(&request.dispatch, artifacts)
    }
}

impl CountingBackend {
    fn calls(&self) -> Result<u32, BackendError> {
        self.calls
            .lock()
            .map(|count| *count)
            .map_err(|_| BackendError::Transport {
                message: "counter poisoned".to_owned(),
            })
    }
}

impl Backend for CountingBackend {
    fn preflight(
        &self,
        _operation: &Operation,
        _profile: &cheirismos::domain::CommissionedProfile,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &DispatchRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        let mut calls = self.calls.lock().map_err(|_| BackendError::Transport {
            message: "counter poisoned".to_owned(),
        })?;
        *calls += 1;
        let mut observation = cheirismos::domain::Observation {
            captured_at: "2099-01-01T00:00:00Z".to_owned(),
            source_fingerprint: digest(b"instrument"),
            body: serde_json::json!({"ok": true}),
            evidence: None,
        };
        let envelope = EvidenceEnvelope {
            attempt: request.attempt.clone(),
            challenge: request.evidence_challenge.clone(),
            phase: request.evidence_phase,
            observation: observation.clone(),
        };
        observation.evidence = Some(
            self.store
                .publish(
                    &serde_json::to_vec(&envelope).map_err(|error| BackendError::Malformed {
                        message: error.to_string(),
                    })?,
                    EvidenceSource::Attempt(request.attempt.clone()),
                )
                .map_err(|error| BackendError::Transport {
                    message: error.to_string(),
                })?,
        );
        Ok(cheirismos::domain::OperationReceipt::Completed { observation })
    }

    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        self.execute(&request.dispatch, artifacts)
    }
}

impl Backend for ReconcileBackend {
    fn preflight(
        &self,
        _operation: &Operation,
        _profile: &cheirismos::domain::CommissionedProfile,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn execute(
        &self,
        _request: &DispatchRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        Err(BackendError::Transport {
            message: "not used".to_owned(),
        })
    }

    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        *self.calls.lock().map_err(|_| BackendError::Transport {
            message: "counter poisoned".to_owned(),
        })? += 1;
        self.configure
            .lock()
            .map_err(|_| BackendError::Transport {
                message: "configure poisoned".to_owned(),
            })?
            .push(request.dispatch.configure_instrument);
        if !self.evidence {
            return Ok(cheirismos::domain::OperationReceipt::Unknown {
                reason: "no witness".to_owned(),
                observation: None,
            });
        }
        let mut observation = cheirismos::domain::Observation {
            captured_at: "2099-01-01T00:00:00Z".to_owned(),
            source_fingerprint: digest(b"instrument"),
            body: serde_json::json!({"reconciled": self.complete}),
            evidence: None,
        };
        let envelope = EvidenceEnvelope {
            attempt: request.attempt.clone(),
            challenge: request.dispatch.evidence_challenge.clone(),
            phase: request.dispatch.evidence_phase,
            observation: observation.clone(),
        };
        observation.evidence = Some(
            self.store
                .publish(
                    &serde_json::to_vec(&envelope).map_err(|error| BackendError::Malformed {
                        message: error.to_string(),
                    })?,
                    EvidenceSource::Attempt(request.attempt.clone()),
                )
                .map_err(|error| BackendError::Transport {
                    message: error.to_string(),
                })?,
        );
        if self.complete {
            Ok(cheirismos::domain::OperationReceipt::Completed { observation })
        } else {
            Ok(cheirismos::domain::OperationReceipt::Partial {
                observation,
                reason: "still indeterminate".to_owned(),
            })
        }
    }
}

impl Backend for ObservationBackend {
    fn preflight(
        &self,
        _operation: &Operation,
        _profile: &cheirismos::domain::CommissionedProfile,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &DispatchRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        *self.calls.lock().map_err(|_| BackendError::Transport {
            message: "counter poisoned".to_owned(),
        })? += 1;
        let mut observation = cheirismos::domain::Observation {
            captured_at: self.captured_at.clone(),
            source_fingerprint: digest(b"instrument"),
            body: self.body.clone(),
            evidence: None,
        };
        let envelope = EvidenceEnvelope {
            attempt: request.attempt.clone(),
            challenge: request.evidence_challenge.clone(),
            phase: request.evidence_phase,
            observation: observation.clone(),
        };
        observation.evidence = Some(
            self.store
                .publish(
                    &serde_json::to_vec(&envelope).map_err(|error| BackendError::Malformed {
                        message: error.to_string(),
                    })?,
                    EvidenceSource::Attempt(request.attempt.clone()),
                )
                .map_err(|error| BackendError::Transport {
                    message: error.to_string(),
                })?,
        );
        Ok(cheirismos::domain::OperationReceipt::Completed { observation })
    }

    fn reconcile(
        &self,
        request: &ReconciliationRequest,
        artifacts: &dyn ArtifactResolver,
    ) -> Result<cheirismos::domain::OperationReceipt, BackendError> {
        self.execute(&request.dispatch, artifacts)
    }
}

fn setup() -> Result<TestContext, Box<dyn std::error::Error>> {
    let store = Arc::new(SqliteStore::open_in_memory()?);
    let directory = tempfile::tempdir()?;
    let artifacts = Arc::new(ArtifactStore::open(directory.keep())?);
    for bytes in [
        b"candidate".as_slice(),
        b"tool".as_slice(),
        b"precondition".as_slice(),
    ] {
        artifacts.publish(bytes, EvidenceSource::Attempt(id("attempt-shared-input")?))?;
    }
    let supervisor = Supervisor::new(store.clone(), artifacts.clone());
    let operator = principal("operator-a", PrincipalRole::Operator)?;
    let agent = principal("agent-a", PrincipalRole::Agent)?;
    let reviewer = principal("reviewer-a", PrincipalRole::Reviewer)?;
    supervisor.commission(&operator, profile()?)?;
    supervisor.issue_grant(&operator, &agent, grant()?)?;
    let proposal = supervisor.propose_plan(
        &agent,
        cheirismos::domain::PlanProposal::from(plan("target-a")?),
    )?;
    let reviewed = supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    assert_eq!(reviewed.review_digest, reviewed.digest()?);
    Ok((supervisor, store, artifacts, operator, agent, reviewer))
}

fn install_interlocked_plan(
    supervisor: &Supervisor,
    store: &SqliteStore,
    agent: &Principal,
    reviewer: &Principal,
    plan_id: &'static str,
    postcondition: Option<ObservationCheck>,
) -> Result<GrantId, Box<dyn std::error::Error>> {
    let status = Operation::InstrumentStatus {
        target: id("target-a")?,
        instrument: id("spi-a")?,
    };
    let check = ObservationCheck::try_new(
        JsonPointer::try_new("/ok")?,
        CheckTest::Boolean { expected: true },
    )?;
    let mut commissioned = store.profile("profile-a")?.ok_or("profile missing")?;
    commissioned.id = format!("profile-{plan_id}").try_into()?;
    commissioned
        .permitted_capabilities
        .insert(Capability::InstrumentStatus);
    commissioned
        .instruments
        .get_mut(&id("spi-a")?)
        .ok_or("binding missing")?
        .qualified_capabilities
        .insert(Capability::InstrumentStatus);
    commissioned.live_interlocks = vec![LiveInterlock::try_new(
        BTreeSet::from([EffectPermission::RawBusTransfer]),
        status.clone(),
        vec![check],
        60_000,
    )?];
    store.save_profile(&commissioned)?;
    let mut delegated = store.grant("grant-a")?.ok_or("grant missing")?;
    delegated.id = format!("grant-{plan_id}").try_into()?;
    delegated.profile = commissioned.id.clone();
    delegated.capabilities.insert(Capability::InstrumentStatus);
    delegated.remaining = Budget::try_new(2, 100, 1_000)?;
    store.save_grant(&delegated)?;
    let mut draft = plan("target-a")?;
    draft.id = id(plan_id)?;
    draft.operations = vec![
        PlannedOperation {
            operation: status,
            max_milliseconds: 100,
            postconditions: Vec::new(),
        },
        PlannedOperation {
            operation: draft.operations[0].operation.clone(),
            max_milliseconds: 100,
            postconditions: postcondition.into_iter().collect(),
        },
    ];
    let proposal = supervisor.propose_plan(agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(reviewer, &proposal.id, &proposal.digest()?)?;
    Ok(delegated.id)
}

#[test]
fn repeat_request_does_not_redispatch() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, _operator, agent, _reviewer) = setup()?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    let request = SubmitRequest {
        attempt: id::<AttemptId>("attempt-a")?,
        request: id::<RequestId>("request-a")?,
        grant: id::<GrantId>("grant-a")?,
        plan: id::<PlanId>("plan-a")?,
        operation_index: 0,
    };
    let ticket = match supervisor.submit(&agent, request.clone())? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("first request already existed".into()),
    };
    let completed = supervisor.execute(&agent, ticket, &backend)?;
    assert_eq!(completed.state, AttemptState::Completed);
    match supervisor.submit(&agent, request)? {
        Submission::Existing(existing) => assert_eq!(existing.state, AttemptState::Completed),
        Submission::Admitted(_) => return Err("duplicate request was admitted".into()),
    }
    assert_eq!(backend.calls()?, 1);
    Ok(())
}

#[test]
fn unauthorized_admission_cannot_create_run() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, operator, agent, _reviewer) = setup()?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    let request = PlanAdmissionRequest {
        run: id("run-authority")?,
        first_attempt: id("attempt-authority")?,
        grant: id("grant-a")?,
        plan: id("plan-a")?,
    };
    assert!(
        supervisor
            .admit_plan(&operator, request.clone(), &backend)
            .is_err()
    );
    let foreign = principal("agent-foreign", PrincipalRole::Agent)?;
    assert!(
        supervisor
            .admit_plan(&foreign, request.clone(), &backend)
            .is_err()
    );
    assert!(supervisor.resume_plan(&agent, &request.run).is_err());
    assert!(supervisor.admit_plan(&agent, request, &backend).is_ok());
    assert_eq!(backend.calls()?, 0);
    Ok(())
}

#[test]
fn public_execute_rejects_invalid_later_step_before_any_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, _operator, agent, reviewer) = setup()?;
    let mut draft = plan("target-a")?;
    draft.id = id("plan-invalid-later")?;
    let mut invalid = draft.operations[0].clone();
    invalid.max_milliseconds = 0;
    draft.operations.push(invalid);
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    let ticket = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-invalid-later")?,
            request: id("request-invalid-later")?,
            grant: id("grant-a")?,
            plan: id("plan-invalid-later")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing".into()),
    };
    let rejected = supervisor.execute(&agent, ticket, &backend)?;
    assert_eq!(rejected.state, AttemptState::Rejected);
    assert_eq!(backend.calls()?, 0);
    Ok(())
}

#[test]
fn resume_after_completed_receipt_before_cursor_update() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("state.sqlite");
    let artifacts = Arc::new(ArtifactStore::open(directory.path().join("evidence"))?);
    let operator = principal("operator-a", PrincipalRole::Operator)?;
    let agent = principal("agent-a", PrincipalRole::Agent)?;
    let reviewer = principal("reviewer-a", PrincipalRole::Reviewer)?;
    let first = id::<AttemptId>("attempt-crash-first")?;
    let second = id::<AttemptId>("attempt-crash-second")?;
    let run = id::<RequestId>("run-crash-gap")?;
    let next_request = id::<RequestId>("request-crash-second")?;
    {
        let store = Arc::new(SqliteStore::open(&database)?);
        let supervisor = Supervisor::new(store.clone(), artifacts.clone());
        supervisor.commission(&operator, profile()?)?;
        supervisor.issue_grant(&operator, &agent, grant()?)?;
        for bytes in [
            b"candidate".as_slice(),
            b"tool".as_slice(),
            b"precondition".as_slice(),
        ] {
            artifacts.publish(bytes, EvidenceSource::Attempt(id("attempt-crash-input")?))?;
        }
        let mut draft = plan("target-a")?;
        draft.id = id("plan-crash-gap")?;
        draft.operations.push(draft.operations[0].clone());
        let proposal =
            supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
        supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
        store.create_run(&PlanRun {
            id: run.clone(),
            agent: agent.id.clone(),
            grant: id("grant-a")?,
            plan: id("plan-crash-gap")?,
            steps: vec![
                (first.clone(), run.clone()),
                (second.clone(), next_request.clone()),
            ],
            cursor: 0,
        })?;
        let backend = CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        };
        let ticket = match supervisor.submit(
            &agent,
            SubmitRequest {
                attempt: first.clone(),
                request: run.clone(),
                grant: id("grant-a")?,
                plan: id("plan-crash-gap")?,
                operation_index: 0,
            },
        )? {
            Submission::Admitted(ticket) => ticket,
            Submission::Existing(_) => return Err("existing".into()),
        };
        assert_eq!(
            supervisor.execute(&agent, ticket, &backend)?.state,
            AttemptState::Completed
        );
        assert_eq!(store.run(&run)?.ok_or("run missing")?.cursor, 0);
    }
    let store = Arc::new(SqliteStore::open(&database)?);
    let supervisor = Supervisor::new(store.clone(), artifacts.clone());
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    let ticket = supervisor.resume_plan(&agent, &run)?;
    let completed = supervisor.execute_next(&agent, ticket, &backend)?;
    assert_eq!(completed.attempt.id, second);
    assert_eq!(completed.attempt.state, AttemptState::Completed);
    assert_eq!(store.run(&run)?.ok_or("run missing")?.cursor, 2);
    assert_eq!(backend.calls()?, 1);
    Ok(())
}

#[test]
fn changed_duplicate_run_preserves_original_cursor_and_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open_in_memory()?;
    let run = PlanRun {
        id: id("run-immutable")?,
        agent: id("agent-a")?,
        grant: id("grant-a")?,
        plan: id("plan-a")?,
        steps: vec![(id("attempt-run-one")?, id("request-run-one")?)],
        cursor: 0,
    };
    store.create_run(&run)?;
    store.advance_run(&run.id, 0)?;
    store.create_run(&run)?;
    assert_eq!(store.run(&run.id)?.ok_or("run missing")?.cursor, 1);
    let mut changed = run.clone();
    changed.plan = id("plan-other")?;
    assert!(store.create_run(&changed).is_err());
    let stored = store.run(&run.id)?.ok_or("run missing")?;
    assert_eq!(stored.plan, run.plan);
    assert_eq!(stored.cursor, 1);
    Ok(())
}

#[test]
fn reissue_cannot_restore_spent_or_revoked_grant_or_recommission_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open_in_memory()?;
    let profile_value = profile()?;
    let grant_value = grant()?;
    store.save_profile(&profile_value)?;
    store.save_grant(&grant_value)?;
    store.revoke_grant(&grant_value.id)?;
    let mut reissued = grant_value.clone();
    reissued.remaining = Budget::try_new(99, 999, 999)?;
    reissued.revoked = false;
    assert!(store.save_grant(&reissued).is_err());
    assert!(
        store
            .grant(grant_value.id.as_str())?
            .ok_or("grant missing")?
            .revoked
    );
    let mut recommissioned = profile_value.clone();
    recommissioned.fixture_revision = digest(b"different-fixture");
    assert!(store.save_profile(&recommissioned).is_err());
    assert_eq!(
        store
            .profile(profile_value.id.as_str())?
            .ok_or("profile missing")?
            .fixture_revision,
        profile_value.fixture_revision
    );
    Ok(())
}

#[test]
fn rejects_wrong_target_and_unreviewed_plan() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, _artifacts, _operator, agent, _reviewer) = setup()?;
    let mut wrong_draft = plan("target-b")?;
    wrong_draft.id = id("plan-wrong")?;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(wrong_draft))?;
    let wrong = supervisor.review_proposal(
        &principal("reviewer-b", PrincipalRole::Reviewer)?,
        &proposal.id,
        &proposal.digest()?,
    )?;
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-wrong")?,
                    request: id("request-wrong")?,
                    grant: id("grant-a")?,
                    plan: wrong.id,
                    operation_index: 0
                }
            )
            .is_err()
    );
    let mut unreviewed = plan("target-a")?;
    unreviewed.id = id("plan-unreviewed")?;
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-unreviewed")?,
                    request: id("request-unreviewed")?,
                    grant: id("grant-a")?,
                    plan: unreviewed.id,
                    operation_index: 0
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn evidence_read_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let artifacts = ArtifactStore::open(directory.path())?;
    let attempt = id::<AttemptId>("attempt-evidence")?;
    let digest = artifacts.publish(b"original", EvidenceSource::Attempt(attempt))?;
    std::fs::write(artifacts.path_for(&digest), b"tampered")?;
    assert!(artifacts.read(&digest).is_err());
    Ok(())
}

#[test]
fn concurrent_duplicate_publication_preserves_content_and_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let artifacts = Arc::new(ArtifactStore::open(directory.path())?);
    let barrier = Arc::new(Barrier::new(2));
    let first_store = artifacts.clone();
    let first_barrier = barrier.clone();
    let first = std::thread::spawn(
        move || -> Result<ArtifactDigest, cheirismos::evidence::EvidenceError> {
            first_barrier.wait();
            first_store.publish(
                b"shared",
                EvidenceSource::Attempt(
                    id("attempt-concurrent-a")
                        .map_err(|source| cheirismos::evidence::EvidenceError::Domain { source })?,
                ),
            )
        },
    );
    barrier.wait();
    let second = artifacts.publish(
        b"shared",
        EvidenceSource::Attempt(id("attempt-concurrent-b")?),
    )?;
    let first = first.join().map_err(|_| "publisher panicked")??;
    assert_eq!(first, second);
    assert_eq!(artifacts.read(&first)?.as_bytes(), b"shared");
    let text = first.as_str();
    let reference_root = directory
        .path()
        .join("references")
        .join("sha256")
        .join(&text[..2])
        .join(&text[2..])
        .join("attempt");
    assert!(reference_root.join("attempt-concurrent-a").exists());
    assert!(reference_root.join("attempt-concurrent-b").exists());
    Ok(())
}

#[test]
fn reopening_dispatched_attempt_marks_it_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite");
    let grant_value = grant()?;
    let profile_value = profile()?;
    let mut plan_value = plan("target-a")?;
    plan_value.review_digest = plan_value.digest()?;
    let attempt = AttemptRecord {
        id: id("attempt-reopen")?,
        request: id("request-reopen")?,
        grant: grant_value.id.clone(),
        plan: plan_value.id.clone(),
        operation_index: 0,
        plan_digest: plan_value.digest()?,
        reserved: Budget::try_new(1, 0, 0)?,
        profile: profile_value.id.clone(),
        profile_digest: profile_value.digest()?,
        leased_resources: profile_value.physical_resources(),
        evidence_challenge: digest(b"challenge"),
        evidence_ordinal: 0,
        state: AttemptState::Intent,
        receipt: None,
        created_at: "2099-01-01T00:00:00Z".to_owned(),
        updated_at: "2099-01-01T00:00:00Z".to_owned(),
    };
    let store = SqliteStore::open(&path)?;
    store.save_grant(&grant_value)?;
    store.save_profile(&profile_value)?;
    store.save_plan(&plan_value)?;
    let snapshot = AdmissionSnapshot {
        agent: id("agent-a")?,
        profile: profile_value,
        plan: plan_value,
    };
    let reservation = store.reserve(&attempt, &snapshot)?;
    assert!(matches!(
        reservation,
        cheirismos::store::ReservationOutcome::Reserved(_)
    ));
    store.claim_dispatch(&attempt.id, &id("agent-a")?)?;
    drop(store);
    let reopened = SqliteStore::open(&path)?;
    let recovered = reopened.attempt(&attempt.id)?.ok_or("attempt missing")?;
    assert_eq!(recovered.state, AttemptState::Unknown);
    Ok(())
}

#[test]
fn rejects_expired_revoked_and_changed_fixture_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let (_supervisor, store, _artifacts, _operator, _agent, _reviewer) = setup()?;
    let mut expired = store.grant("grant-a")?.ok_or("grant missing")?;
    expired.expires_at = "2000-01-01T00:00:00Z".to_owned();
    assert!(store.save_grant(&expired).is_err());

    let (supervisor, _store, _artifacts, operator, agent, _reviewer) = setup()?;
    supervisor.revoke_grant(&operator, &id("grant-a")?)?;
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-revoked")?,
                    request: id("request-revoked")?,
                    grant: id("grant-a")?,
                    plan: id("plan-a")?,
                    operation_index: 0
                }
            )
            .is_err()
    );

    let (_supervisor, store, _artifacts, _operator, _agent, _reviewer) = setup()?;
    let mut changed = store.profile("profile-a")?.ok_or("profile missing")?;
    changed.fixture_revision = digest(b"new-fixture");
    assert!(store.save_profile(&changed).is_err());
    Ok(())
}

#[test]
fn records_partial_receipts_without_synthetic_success() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, _operator, agent, _reviewer) = setup()?;
    let ticket = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-partial")?,
            request: id("request-partial")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("unexpected existing attempt".into()),
    };
    let attempt = supervisor.execute(&agent, ticket, &PartialBackend { store: artifacts })?;
    assert_eq!(attempt.state, AttemptState::Partial);
    Ok(())
}

#[test]
fn reconciliation_is_idempotent_and_retains_original_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, _operator, agent, _reviewer) = setup()?;
    let ticket = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-reconcile")?,
            request: id("request-effect")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing".into()),
    };
    let partial = supervisor.execute(
        &agent,
        ticket,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;
    assert_eq!(partial.state, AttemptState::Partial);
    let backend = ReconcileBackend {
        store: artifacts,
        calls: Mutex::new(0),
        configure: Mutex::new(Vec::new()),
        complete: false,
        evidence: true,
    };
    let request = id::<RequestId>("request-reconcile")?;
    let reconciled = supervisor.reconcile(&agent, &partial.id, &request, &backend)?;
    assert_eq!(reconciled.state, AttemptState::Unknown);
    assert!(matches!(
        reconciled.receipt,
        Some(cheirismos::domain::OperationReceipt::Partial { .. })
    ));
    let again = supervisor.reconcile(&agent, &partial.id, &request, &backend)?;
    assert_eq!(again.state, AttemptState::Unknown);
    assert_eq!(*backend.calls.lock().map_err(|_| "counter poisoned")?, 1);
    assert_eq!(
        *backend.configure.lock().map_err(|_| "configure poisoned")?,
        vec![false]
    );
    let history = store.reconciliation_history(&partial.id)?;
    assert_eq!(history.len(), 1);
    assert!(matches!(
        history[0].receipt,
        Some(cheirismos::domain::OperationReceipt::Partial { .. })
    ));
    Ok(())
}

#[test]
fn reconciliation_without_evidence_cannot_resolve_uncertainty()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, _operator, agent, _reviewer) = setup()?;
    let ticket = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-no-evidence")?,
            request: id("request-no-evidence-effect")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing".into()),
    };
    let partial = supervisor.execute(
        &agent,
        ticket,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;
    let backend = ReconcileBackend {
        store: artifacts,
        calls: Mutex::new(0),
        configure: Mutex::new(Vec::new()),
        complete: true,
        evidence: false,
    };
    assert!(
        supervisor
            .reconcile(&agent, &partial.id, &id("request-no-evidence")?, &backend)
            .is_err()
    );
    assert_eq!(
        supervisor
            .attempt(&partial.id)?
            .ok_or("attempt missing")?
            .state,
        AttemptState::Unknown
    );
    let history = store.reconciliation_history(&partial.id)?;
    assert_eq!(history.len(), 1);
    assert!(history[0].receipt.is_none());
    Ok(())
}

#[test]
fn reviewed_configuration_setup_is_charged_and_explicit() -> Result<(), Box<dyn std::error::Error>>
{
    let (supervisor, store, artifacts, _operator, agent, reviewer) = setup()?;
    let mut draft = plan("target-a")?;
    draft.id = id("plan-configure-reconcile")?;
    draft.reconciliation_setup = ReconciliationSetup::ApplyReviewedInstrumentConfiguration;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let ticket = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-configure-reconcile")?,
            request: id("request-configure-effect")?,
            grant: id("grant-a")?,
            plan: id("plan-configure-reconcile")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing".into()),
    };
    let partial = supervisor.execute(
        &agent,
        ticket,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;
    let backend = ReconcileBackend {
        store: artifacts,
        calls: Mutex::new(0),
        configure: Mutex::new(Vec::new()),
        complete: true,
        evidence: true,
    };
    let completed = supervisor.reconcile(
        &agent,
        &partial.id,
        &id("request-configure-reconcile")?,
        &backend,
    )?;
    assert_eq!(completed.state, AttemptState::Completed);
    assert_eq!(
        *backend.configure.lock().map_err(|_| "configure poisoned")?,
        vec![true]
    );
    assert_eq!(
        store
            .grant("grant-a")?
            .ok_or("grant missing")?
            .remaining
            .effects,
        7
    );
    Ok(())
}

#[test]
fn authority_takeover_transfers_lease_without_rewriting_uncertainty()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let source = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-recovery-source")?,
            request: id("request-recovery-source")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing".into()),
    };
    let unresolved = supervisor.execute(
        &agent,
        source,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;
    let mut recovery_grant = grant()?;
    recovery_grant.id = id("grant-recovery")?;
    recovery_grant.remaining = Budget::try_new(2, 100, 1000)?;
    supervisor.issue_grant(&operator, &agent, recovery_grant)?;
    let mut replacement = plan("target-a")?;
    replacement.id = id("plan-recovery")?;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(replacement))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    for bytes in [
        b"candidate".as_slice(),
        b"tool".as_slice(),
        b"precondition".as_slice(),
    ] {
        artifacts.publish(
            bytes,
            EvidenceSource::Attempt(id("attempt-recovery-input")?),
        )?;
    }
    let justification = artifacts.publish(
        b"recovery justification",
        EvidenceSource::Attempt(id("attempt-justification")?),
    )?;
    let recovery = RecoveryTakeoverRequest {
        request: id("request-takeover")?,
        run: id("run-takeover")?,
        first_attempt: id("attempt-recovery")?,
        unresolved: vec![unresolved.id.clone()],
        grant: id("grant-recovery")?,
        plan: id("plan-recovery")?,
        justification_evidence: justification,
    };
    assert!(
        supervisor
            .takeover_recovery(
                &agent,
                recovery.clone(),
                &CountingBackend {
                    calls: Mutex::new(0),
                    store: artifacts.clone()
                },
            )
            .is_err()
    );
    let reconciliation_request: RequestId = id("request-takeover-reconcile")?;
    match store.claim_reconciliation(&unresolved.id, &reconciliation_request, &agent.id, None)? {
        cheirismos::store::ReconciliationClaim::Claimed(_) => {}
        cheirismos::store::ReconciliationClaim::Existing(_) => {
            return Err("unexpected existing reconciliation".into());
        }
    }
    assert!(
        supervisor
            .takeover_recovery(
                &operator,
                recovery.clone(),
                &CountingBackend {
                    calls: Mutex::new(0),
                    store: artifacts.clone()
                },
            )
            .is_err()
    );
    store.finish_reconciliation(&reconciliation_request, None, false, false)?;
    let _ticket = supervisor.takeover_recovery(
        &operator,
        recovery.clone(),
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    let original = supervisor
        .attempt(&unresolved.id)?
        .ok_or("source missing")?;
    assert_eq!(original.state, AttemptState::Unknown);
    assert_eq!(original.receipt, unresolved.receipt);
    let duplicate = supervisor.takeover_recovery(
        &operator,
        recovery.clone(),
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    let admitted = supervisor
        .attempt(&id("attempt-recovery")?)?
        .ok_or("recovery missing")?;
    assert_eq!(admitted.state, AttemptState::Intent);
    assert_eq!(
        store
            .grant("grant-recovery")?
            .ok_or("grant missing")?
            .remaining
            .effects,
        0
    );
    let mut altered = recovery;
    altered.plan = id("plan-a")?;
    assert!(
        supervisor
            .takeover_recovery(
                &operator,
                altered,
                &CountingBackend {
                    calls: Mutex::new(0),
                    store: artifacts.clone()
                },
            )
            .is_err()
    );
    let _ = duplicate;
    Ok(())
}

#[test]
fn inherited_recovery_lease_requires_a_reviewed_takeover_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let source = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-chain-a")?,
            request: id("request-chain-a")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing source".into()),
    };
    let unknown = supervisor.execute(
        &agent,
        source,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;

    let mut grant_b = grant()?;
    grant_b.id = id("grant-chain-b")?;
    grant_b.remaining = Budget::try_new(4, 100, 1_000)?;
    supervisor.issue_grant(&operator, &agent, grant_b)?;
    let mut plan_b = plan("target-a")?;
    plan_b.id = id("plan-chain-b")?;
    plan_b.operations.push(plan_b.operations[0].clone());
    let proposal_b =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(plan_b))?;
    supervisor.review_proposal(&reviewer, &proposal_b.id, &proposal_b.digest()?)?;
    let justification_a = artifacts.publish(
        b"chain handoff A to B",
        EvidenceSource::Attempt(id("attempt-chain-justification-a")?),
    )?;
    let recovery_b = RecoveryTakeoverRequest {
        request: id("request-chain-b")?,
        run: id("run-chain-b")?,
        first_attempt: id("attempt-chain-b")?,
        unresolved: vec![unknown.id.clone()],
        grant: id("grant-chain-b")?,
        plan: id("plan-chain-b")?,
        justification_evidence: justification_a,
    };
    let ticket_b = supervisor.takeover_recovery(
        &operator,
        recovery_b.clone(),
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    let abandon_justification = artifacts.publish(
        b"recovery destination must not be abandoned",
        EvidenceSource::Attempt(id("attempt-chain-abandonment")?),
    )?;
    assert!(
        supervisor
            .abandon_halted_run(
                &operator,
                HaltedRunAbandonmentRequest {
                    request: id("request-chain-abandonment")?,
                    run: id("run-chain-b")?,
                    grant: id("grant-chain-b")?,
                    plan: id("plan-chain-b")?,
                    justification_evidence: abandon_justification,
                },
            )
            .is_err()
    );
    let b_backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts.clone(),
    };
    let b_progress = supervisor.execute_next(&agent, ticket_b, &b_backend)?;
    assert_eq!(b_progress.attempt.state, AttemptState::Completed);
    let second_b = store
        .run(&id("run-chain-b")?)?
        .ok_or("recovery run missing")?
        .steps
        .get(1)
        .ok_or("recovery second step missing")?
        .0
        .clone();
    store.reject_intent(&second_b, "pre-effect rejection".to_owned())?;

    let mut grant_c = grant()?;
    grant_c.id = id("grant-chain-c")?;
    grant_c.remaining = Budget::try_new(2, 100, 1_000)?;
    supervisor.issue_grant(&operator, &agent, grant_c)?;
    let mut plan_c = plan("target-a")?;
    plan_c.id = id("plan-chain-c")?;
    let proposal_c =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(plan_c))?;
    supervisor.review_proposal(&reviewer, &proposal_c.id, &proposal_c.digest()?)?;
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-chain-unrelated")?,
                    request: id("request-chain-unrelated")?,
                    grant: id("grant-chain-c")?,
                    plan: id("plan-chain-c")?,
                    operation_index: 0,
                },
            )
            .is_err()
    );
    let justification_b = artifacts.publish(
        b"chain handoff B to C",
        EvidenceSource::Attempt(id("attempt-chain-justification-b")?),
    )?;
    let ticket_c = supervisor.takeover_recovery(
        &operator,
        RecoveryTakeoverRequest {
            request: id("request-chain-c")?,
            run: id("run-chain-c")?,
            first_attempt: id("attempt-chain-c")?,
            unresolved: vec![second_b],
            grant: id("grant-chain-c")?,
            plan: id("plan-chain-c")?,
            justification_evidence: justification_b,
        },
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    assert!(store.is_recovery_source_retired(&id("grant-a")?, &id("plan-a")?)?);
    assert!(store.is_recovery_source_retired(&id("grant-chain-b")?, &id("plan-chain-b")?)?);
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    assert_eq!(
        supervisor
            .execute_next(&agent, ticket_c, &backend)?
            .attempt
            .state,
        AttemptState::Completed
    );
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-chain-a-revive")?,
                    request: id("request-chain-a-revive")?,
                    grant: id("grant-a")?,
                    plan: id("plan-a")?,
                    operation_index: 0,
                },
            )
            .is_err()
    );
    assert!(
        supervisor
            .submit(
                &agent,
                SubmitRequest {
                    attempt: id("attempt-chain-b-revive")?,
                    request: id("request-chain-b-revive")?,
                    grant: id("grant-chain-b")?,
                    plan: id("plan-chain-b")?,
                    operation_index: 0,
                },
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_takeover_refuses_pair_with_another_active_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let source = match supervisor.submit(
        &agent,
        SubmitRequest {
            attempt: id("attempt-pair-active-a")?,
            request: id("request-pair-active-a")?,
            grant: id("grant-a")?,
            plan: id("plan-a")?,
            operation_index: 0,
        },
    )? {
        Submission::Admitted(ticket) => ticket,
        Submission::Existing(_) => return Err("existing source".into()),
    };
    let source = supervisor.execute(
        &agent,
        source,
        &PartialBackend {
            store: artifacts.clone(),
        },
    )?;
    let mut grant_b = grant()?;
    grant_b.id = id("grant-pair-active-b")?;
    grant_b.remaining = Budget::try_new(4, 100, 1_000)?;
    supervisor.issue_grant(&operator, &agent, grant_b)?;
    let mut plan_b = plan("target-a")?;
    plan_b.id = id("plan-pair-active-b")?;
    plan_b.operations.push(plan_b.operations[0].clone());
    let proposal_b =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(plan_b))?;
    supervisor.review_proposal(&reviewer, &proposal_b.id, &proposal_b.digest()?)?;
    let ticket_b = supervisor.takeover_recovery(
        &operator,
        RecoveryTakeoverRequest {
            request: id("request-pair-active-b")?,
            run: id("run-pair-active-b")?,
            first_attempt: id("attempt-pair-active-b")?,
            unresolved: vec![source.id],
            grant: id("grant-pair-active-b")?,
            plan: id("plan-pair-active-b")?,
            justification_evidence: artifacts.publish(
                b"pair active A to B",
                EvidenceSource::Attempt(id("attempt-pair-active-justification-a")?),
            )?,
        },
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    let completed_prefix = supervisor.execute_next(
        &agent,
        ticket_b,
        &CountingBackend {
            calls: Mutex::new(0),
            store: artifacts.clone(),
        },
    )?;
    let second_b = store
        .run(&id("run-pair-active-b")?)?
        .ok_or("recovery run missing")?
        .steps
        .get(1)
        .ok_or("second recovery step missing")?
        .0
        .clone();
    store.claim_dispatch(&second_b, &agent.id)?;
    store.record_receipt(
        &second_b,
        OperationReceipt::Partial {
            observation: Observation {
                captured_at: "2099-01-01T00:00:00Z".to_owned(),
                source_fingerprint: digest(b"instrument"),
                body: serde_json::json!({"partial": true}),
                evidence: None,
            },
            reason: "requires reconciliation".to_owned(),
        },
        false,
    )?;
    let reconciliation: RequestId = id("request-pair-active-reconciliation")?;
    assert!(matches!(
        store.claim_reconciliation(&second_b, &reconciliation, &agent.id, None)?,
        cheirismos::store::ReconciliationClaim::Claimed(_)
    ));
    let mut grant_c = grant()?;
    grant_c.id = id("grant-pair-active-c")?;
    grant_c.remaining = Budget::try_new(2, 100, 1_000)?;
    supervisor.issue_grant(&operator, &agent, grant_c)?;
    let mut plan_c = plan("target-a")?;
    plan_c.id = id("plan-pair-active-c")?;
    let proposal_c =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(plan_c))?;
    supervisor.review_proposal(&reviewer, &proposal_c.id, &proposal_c.digest()?)?;
    assert!(
        supervisor
            .takeover_recovery(
                &operator,
                RecoveryTakeoverRequest {
                    request: id("request-pair-active-c")?,
                    run: id("run-pair-active-c")?,
                    first_attempt: id("attempt-pair-active-c")?,
                    unresolved: vec![completed_prefix.attempt.id],
                    grant: id("grant-pair-active-c")?,
                    plan: id("plan-pair-active-c")?,
                    justification_evidence: artifacts.publish(
                        b"pair active B to C",
                        EvidenceSource::Attempt(id("attempt-pair-active-justification-b")?),
                    )?,
                },
                &CountingBackend {
                    calls: Mutex::new(0),
                    store: artifacts,
                },
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_takeover_rejects_ordinary_or_dispatched_nonrecovery_sources()
-> Result<(), Box<dyn std::error::Error>> {
    for (suffix, dispatched) in [("intent", false), ("dispatched", true)] {
        let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
        let source_attempt: AttemptId = format!("attempt-source-{suffix}").try_into()?;
        let source_request: RequestId = format!("request-source-{suffix}").try_into()?;
        let source = match supervisor.submit(
            &agent,
            SubmitRequest {
                attempt: source_attempt.clone(),
                request: source_request,
                grant: id("grant-a")?,
                plan: id("plan-a")?,
                operation_index: 0,
            },
        )? {
            Submission::Admitted(ticket) => ticket,
            Submission::Existing(_) => return Err("existing source".into()),
        };
        if dispatched {
            store.claim_dispatch(&source_attempt, &agent.id)?;
        }
        let mut replacement_grant = grant()?;
        replacement_grant.id = format!("grant-source-{suffix}").try_into()?;
        replacement_grant.remaining = Budget::try_new(2, 100, 1_000)?;
        supervisor.issue_grant(&operator, &agent, replacement_grant)?;
        let mut replacement = plan("target-a")?;
        replacement.id = format!("plan-source-{suffix}").try_into()?;
        let proposal =
            supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(replacement))?;
        supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
        let justification = artifacts.publish(
            suffix.as_bytes(),
            EvidenceSource::Attempt(format!("attempt-source-justification-{suffix}").try_into()?),
        )?;
        assert!(
            supervisor
                .takeover_recovery(
                    &operator,
                    RecoveryTakeoverRequest {
                        request: format!("request-source-takeover-{suffix}").try_into()?,
                        run: format!("run-source-takeover-{suffix}").try_into()?,
                        first_attempt: format!("attempt-source-takeover-{suffix}").try_into()?,
                        unresolved: vec![source_attempt],
                        grant: format!("grant-source-{suffix}").try_into()?,
                        plan: format!("plan-source-{suffix}").try_into()?,
                        justification_evidence: justification,
                    },
                    &CountingBackend {
                        calls: Mutex::new(0),
                        store: artifacts,
                    },
                )
                .is_err()
        );
        let _ = source;
    }
    Ok(())
}

#[test]
fn fresh_interlock_gates_effect_and_failed_postcondition_stays_partial()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, _operator, agent, reviewer) = setup()?;
    let failed = ObservationCheck::try_new(
        JsonPointer::try_new("/ok")?,
        CheckTest::Boolean { expected: false },
    )?;
    let interlock_grant = install_interlocked_plan(
        &supervisor,
        &_store,
        &agent,
        &reviewer,
        "plan-interlocked",
        Some(failed),
    )?;
    for bytes in [
        b"candidate".as_slice(),
        b"tool".as_slice(),
        b"precondition".as_slice(),
    ] {
        artifacts.publish(
            bytes,
            EvidenceSource::Attempt(id("attempt-interlock-input")?),
        )?;
    }
    let backend = ObservationBackend {
        store: artifacts,
        calls: Mutex::new(0),
        captured_at: jiff::Timestamp::now().to_string(),
        body: serde_json::json!({"ok": true}),
    };
    let ticket = supervisor.admit_plan(
        &agent,
        PlanAdmissionRequest {
            run: id("run-interlocked")?,
            first_attempt: id("attempt-interlock-status")?,
            grant: interlock_grant,
            plan: id("plan-interlocked")?,
        },
        &backend,
    )?;
    let first = supervisor.execute_next(&agent, ticket, &backend)?;
    let second = first.next.ok_or("missing effect step")?;
    let final_step = supervisor.execute_next(&agent, second, &backend)?;
    assert_eq!(final_step.attempt.state, AttemptState::Partial);
    assert!(final_step.next.is_none());
    assert_eq!(*backend.calls.lock().map_err(|_| "counter poisoned")?, 2);
    Ok(())
}

#[test]
fn stale_or_wrong_interlock_blocks_effect_before_backend_call()
-> Result<(), Box<dyn std::error::Error>> {
    for (suffix, captured_at, body) in [
        (
            "stale",
            jiff::Timestamp::from_millisecond(jiff::Timestamp::now().as_millisecond() - 61_000)?
                .to_string(),
            serde_json::json!({"ok": true}),
        ),
        (
            "wrong",
            jiff::Timestamp::now().to_string(),
            serde_json::json!({"ok": false}),
        ),
    ] {
        let (supervisor, store, artifacts, _operator, agent, reviewer) = setup()?;
        let plan_id = if suffix == "stale" {
            "plan-interlock-stale"
        } else {
            "plan-interlock-wrong"
        };
        let interlock_grant =
            install_interlocked_plan(&supervisor, &store, &agent, &reviewer, plan_id, None)?;
        for bytes in [
            b"candidate".as_slice(),
            b"tool".as_slice(),
            b"precondition".as_slice(),
        ] {
            artifacts.publish(
                bytes,
                EvidenceSource::Attempt(id("attempt-interlock-input-two")?),
            )?;
        }
        let backend = ObservationBackend {
            store: artifacts,
            calls: Mutex::new(0),
            captured_at,
            body,
        };
        let ticket = supervisor.admit_plan(
            &agent,
            PlanAdmissionRequest {
                run: if suffix == "stale" {
                    id("run-interlock-stale")?
                } else {
                    id("run-interlock-wrong")?
                },
                first_attempt: if suffix == "stale" {
                    id("attempt-interlock-stale")?
                } else {
                    id("attempt-interlock-wrong")?
                },
                grant: interlock_grant,
                plan: id(plan_id)?,
            },
            &backend,
        )?;
        let first = supervisor.execute_next(&agent, ticket, &backend)?;
        let blocked =
            supervisor.execute_next(&agent, first.next.ok_or("missing effect")?, &backend)?;
        assert_eq!(blocked.attempt.state, AttemptState::Rejected);
        assert_eq!(*backend.calls.lock().map_err(|_| "counter poisoned")?, 1);
    }
    Ok(())
}

#[test]
fn admission_rejects_missing_or_intervening_interlock_observation()
-> Result<(), Box<dyn std::error::Error>> {
    for (suffix, operations) in [
        (
            "missing",
            vec![plan("target-a")?.operations[0].operation.clone()],
        ),
        (
            "intervening",
            vec![
                Operation::InstrumentStatus {
                    target: id("target-a")?,
                    instrument: id("spi-a")?,
                },
                Operation::GpioSet {
                    target: id("target-a")?,
                    instrument: id("spi-a")?,
                    pin: 1,
                    high: true,
                },
                plan("target-a")?.operations[0].operation.clone(),
            ],
        ),
    ] {
        let (supervisor, store, artifacts, _operator, agent, reviewer) = setup()?;
        let interlock_grant = install_interlocked_plan(
            &supervisor,
            &store,
            &agent,
            &reviewer,
            "plan-interlock-primer",
            None,
        )?;
        for bytes in [
            b"candidate".as_slice(),
            b"tool".as_slice(),
            b"precondition".as_slice(),
        ] {
            artifacts.publish(
                bytes,
                EvidenceSource::Attempt(id("attempt-interlock-static-input")?),
            )?;
        }
        let mut draft = plan("target-a")?;
        draft.id = if suffix == "missing" {
            id("plan-interlock-missing")?
        } else {
            id("plan-interlock-intervening")?
        };
        draft.operations = operations
            .into_iter()
            .map(|operation| PlannedOperation {
                operation,
                max_milliseconds: 100,
                postconditions: Vec::new(),
            })
            .collect();
        let proposal =
            supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
        supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
        let backend = ObservationBackend {
            store: artifacts,
            calls: Mutex::new(0),
            captured_at: jiff::Timestamp::now().to_string(),
            body: serde_json::json!({"ok": true}),
        };
        assert!(
            supervisor
                .admit_plan(
                    &agent,
                    PlanAdmissionRequest {
                        run: if suffix == "missing" {
                            id("run-interlock-missing")?
                        } else {
                            id("run-interlock-intervening")?
                        },
                        first_attempt: if suffix == "missing" {
                            id("attempt-interlock-missing")?
                        } else {
                            id("attempt-interlock-intervening")?
                        },
                        grant: interlock_grant.clone(),
                        plan: if suffix == "missing" {
                            id("plan-interlock-missing")?
                        } else {
                            id("plan-interlock-intervening")?
                        },
                    },
                    &backend
                )
                .is_err()
        );
        assert_eq!(*backend.calls.lock().map_err(|_| "counter poisoned")?, 0);
    }
    Ok(())
}

#[test]
fn plan_admission_derives_bounded_step_ids_for_maximum_run_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, _store, artifacts, _operator, agent, reviewer) = setup()?;
    for bytes in [
        b"candidate".as_slice(),
        b"tool".as_slice(),
        b"precondition".as_slice(),
    ] {
        artifacts.publish(bytes, EvidenceSource::Attempt(id("attempt-input")?))?;
    }
    let mut draft = plan("target-a")?;
    draft.id = id("plan-cursor")?;
    draft.operations.push(draft.operations[0].clone());
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let run: RequestId = "r".repeat(128).try_into()?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts,
    };
    let ticket = supervisor.admit_plan(
        &agent,
        PlanAdmissionRequest {
            run,
            first_attempt: id("attempt-cursor")?,
            grant: id("grant-a")?,
            plan: id("plan-cursor")?,
        },
        &backend,
    )?;
    let progress = supervisor.execute_next(&agent, ticket, &backend)?;
    assert_eq!(progress.attempt.state, AttemptState::Completed);
    assert!(progress.next.is_some());
    Ok(())
}

#[test]
fn operator_abandons_revoked_undispatched_intent_without_replaying_it()
-> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let mut draft = plan("target-a")?;
    draft.id = id("plan-halted-intent")?;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts.clone(),
    };
    let _ticket = supervisor.admit_plan(
        &agent,
        PlanAdmissionRequest {
            run: id("run-halted-intent")?,
            first_attempt: id("attempt-halted-intent")?,
            grant: id("grant-a")?,
            plan: id("plan-halted-intent")?,
        },
        &backend,
    )?;
    supervisor.revoke_grant(&operator, &id("grant-a")?)?;
    assert!(
        store
            .claim_dispatch(&id("attempt-halted-intent")?, &agent.id)
            .is_err()
    );
    assert_eq!(backend.calls()?, 0);
    let justification = artifacts.publish(
        b"halted before dispatch",
        EvidenceSource::Attempt(id("attempt-halted-intent-justification")?),
    )?;
    let request = HaltedRunAbandonmentRequest {
        request: id("request-abandon-intent")?,
        run: id("run-halted-intent")?,
        grant: id("grant-a")?,
        plan: id("plan-halted-intent")?,
        justification_evidence: justification.clone(),
    };
    let abandonment = supervisor.abandon_halted_run(&operator, request.clone())?;
    assert!(!abandonment.resources.is_empty());
    assert_eq!(
        supervisor
            .attempt(&id("attempt-halted-intent")?)?
            .ok_or("intent missing")?
            .state,
        AttemptState::Rejected
    );
    assert_eq!(
        supervisor.abandon_halted_run(&operator, request.clone())?,
        abandonment
    );
    let mut conflicting = request.clone();
    conflicting.justification_evidence = artifacts.publish(
        b"different justification",
        EvidenceSource::Attempt(id("attempt-halted-intent-conflict")?),
    )?;
    assert!(
        supervisor
            .abandon_halted_run(&operator, conflicting)
            .is_err()
    );
    assert!(supervisor.resume_plan(&agent, &request.run).is_err());
    assert!(
        supervisor
            .admit_plan(
                &agent,
                PlanAdmissionRequest {
                    run: id("run-halted-intent-retry")?,
                    first_attempt: id("attempt-halted-intent-retry")?,
                    grant: id("grant-a")?,
                    plan: id("plan-halted-intent")?,
                },
                &backend,
            )
            .is_err()
    );
    assert!(
        store
            .claim_dispatch(&id("attempt-halted-intent")?, &agent.id)
            .is_err()
    );
    assert_eq!(backend.calls()?, 0);

    let mut successor_grant = grant()?;
    successor_grant.id = id("grant-after-halt")?;
    successor_grant.remaining = Budget::try_new(10, 1_000, 10_000)?;
    supervisor.issue_grant(&operator, &agent, successor_grant)?;
    let mut successor_draft = plan("target-a")?;
    successor_draft.id = id("plan-after-halt")?;
    let successor_proposal = supervisor.propose_plan(
        &agent,
        cheirismos::domain::PlanProposal::from(successor_draft),
    )?;
    supervisor.review_proposal(
        &reviewer,
        &successor_proposal.id,
        &successor_proposal.digest()?,
    )?;
    assert!(
        supervisor
            .admit_plan(
                &agent,
                PlanAdmissionRequest {
                    run: id("run-after-halt")?,
                    first_attempt: id("attempt-after-halt")?,
                    grant: id("grant-after-halt")?,
                    plan: id("plan-after-halt")?,
                },
                &backend,
            )
            .is_ok()
    );
    assert!(
        store
            .halted_run_abandonment(&id("run-halted-intent")?)?
            .is_some()
    );
    Ok(())
}

#[test]
fn operator_abandons_expired_undispatched_intent() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let mut expiring_grant = grant()?;
    expiring_grant.id = id("grant-halted-expired")?;
    expiring_grant.expires_at = jiff::Timestamp::now()
        .saturating_add(jiff::Span::new().seconds(1))
        .map_err(|error| format!("expiration: {error}"))?
        .to_string();
    supervisor.issue_grant(&operator, &agent, expiring_grant)?;
    let mut draft = plan("target-a")?;
    draft.id = id("plan-halted-expired")?;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts.clone(),
    };
    supervisor.admit_plan(
        &agent,
        PlanAdmissionRequest {
            run: id("run-halted-expired")?,
            first_attempt: id("attempt-halted-expired")?,
            grant: id("grant-halted-expired")?,
            plan: id("plan-halted-expired")?,
        },
        &backend,
    )?;
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert!(
        store
            .claim_dispatch(&id("attempt-halted-expired")?, &agent.id)
            .is_err()
    );
    let justification = artifacts.publish(
        b"grant expired before dispatch",
        EvidenceSource::Attempt(id("attempt-halted-expired-justification")?),
    )?;
    supervisor.abandon_halted_run(
        &operator,
        HaltedRunAbandonmentRequest {
            request: id("request-abandon-expired")?,
            run: id("run-halted-expired")?,
            grant: id("grant-halted-expired")?,
            plan: id("plan-halted-expired")?,
            justification_evidence: justification,
        },
    )?;
    assert_eq!(
        supervisor
            .attempt(&id("attempt-halted-expired")?)?
            .ok_or("expired intent missing")?
            .state,
        AttemptState::Rejected
    );
    assert_eq!(backend.calls()?, 0);
    Ok(())
}

#[test]
fn abandonment_refuses_unresolved_or_inflight_attempts() -> Result<(), Box<dyn std::error::Error>> {
    let (supervisor, store, artifacts, operator, agent, reviewer) = setup()?;
    let mut draft = plan("target-a")?;
    draft.id = id("plan-abandon-inflight")?;
    let proposal =
        supervisor.propose_plan(&agent, cheirismos::domain::PlanProposal::from(draft))?;
    supervisor.review_proposal(&reviewer, &proposal.id, &proposal.digest()?)?;
    let backend = CountingBackend {
        calls: Mutex::new(0),
        store: artifacts.clone(),
    };
    let _ticket = supervisor.admit_plan(
        &agent,
        PlanAdmissionRequest {
            run: id("run-abandon-inflight")?,
            first_attempt: id("attempt-abandon-inflight")?,
            grant: id("grant-a")?,
            plan: id("plan-abandon-inflight")?,
        },
        &backend,
    )?;
    store.claim_dispatch(&id("attempt-abandon-inflight")?, &agent.id)?;
    let justification = artifacts.publish(
        b"must not release active work",
        EvidenceSource::Attempt(id("attempt-abandon-inflight-justification")?),
    )?;
    let request = HaltedRunAbandonmentRequest {
        request: id("request-abandon-inflight")?,
        run: id("run-abandon-inflight")?,
        grant: id("grant-a")?,
        plan: id("plan-abandon-inflight")?,
        justification_evidence: justification,
    };
    assert!(
        supervisor
            .abandon_halted_run(&agent, request.clone())
            .is_err()
    );
    assert!(supervisor.abandon_halted_run(&operator, request).is_err());
    assert_eq!(
        supervisor
            .attempt(&id("attempt-abandon-inflight")?)?
            .ok_or("attempt missing")?
            .state,
        AttemptState::Dispatched
    );
    Ok(())
}

#[test]
fn completed_prefix_halt_survives_reopen_then_releases_only_its_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("halted.sqlite");
    let profile_value = profile()?;
    let grant_value = grant()?;
    let mut plan_value = plan("target-a")?;
    plan_value.id = id("plan-halted-reopen")?;
    plan_value.operations.push(plan_value.operations[0].clone());
    plan_value.review_digest = plan_value.digest()?;
    let run: RequestId = id("run-halted-reopen")?;
    let first: AttemptId = id("attempt-halted-reopen")?;
    let store = SqliteStore::open(&database)?;
    store.save_profile(&profile_value)?;
    store.save_grant(&grant_value)?;
    store.save_plan(&plan_value)?;
    store.create_run(&PlanRun {
        id: run.clone(),
        agent: id("agent-a")?,
        grant: grant_value.id.clone(),
        plan: plan_value.id.clone(),
        steps: vec![
            (first.clone(), id("request-halted-reopen")?),
            (
                id("attempt-halted-reopen-next")?,
                id("request-halted-reopen-next")?,
            ),
        ],
        cursor: 0,
    })?;
    let attempt = AttemptRecord {
        id: first.clone(),
        request: id("request-halted-reopen")?,
        grant: grant_value.id.clone(),
        plan: plan_value.id.clone(),
        operation_index: 0,
        plan_digest: plan_value.digest()?,
        reserved: Budget::try_new(4, 4, 400)?,
        profile: profile_value.id.clone(),
        profile_digest: profile_value.digest()?,
        leased_resources: profile_value.physical_resources(),
        evidence_challenge: digest(b"halted-reopen-challenge"),
        evidence_ordinal: 0,
        state: AttemptState::Intent,
        receipt: None,
        created_at: "2099-01-01T00:00:00Z".to_owned(),
        updated_at: "2099-01-01T00:00:00Z".to_owned(),
    };
    store.reserve(
        &attempt,
        &AdmissionSnapshot {
            agent: id("agent-a")?,
            profile: profile_value.clone(),
            plan: plan_value.clone(),
        },
    )?;
    store.claim_dispatch(&first, &id("agent-a")?)?;
    store.record_receipt(
        &first,
        OperationReceipt::Completed {
            observation: Observation {
                captured_at: "2099-01-01T00:00:00Z".to_owned(),
                source_fingerprint: digest(b"instrument"),
                body: serde_json::json!({"completed": true}),
                evidence: None,
            },
        },
        false,
    )?;
    drop(store);

    let reopened = Arc::new(SqliteStore::open(&database)?);
    assert_eq!(reopened.repair_run_cursor(&run)?.cursor, 1);
    // The next durable step cannot be admitted after this authority change,
    // leaving the completed prefix holding its plan-wide lease across restart.
    reopened.revoke_grant(&grant_value.id)?;
    let artifacts = Arc::new(ArtifactStore::open(directory.path().join("artifacts"))?);
    let justification = artifacts.publish(
        b"halted after completed prefix",
        EvidenceSource::Attempt(id("attempt-halted-reopen-justification")?),
    )?;
    let supervisor = Supervisor::new(reopened.clone(), artifacts);
    let operator = principal("operator-a", PrincipalRole::Operator)?;
    let agent = principal("agent-a", PrincipalRole::Agent)?;
    assert!(supervisor.resume_plan(&agent, &run).is_err());
    let abandonment = supervisor.abandon_halted_run(
        &operator,
        HaltedRunAbandonmentRequest {
            request: id("request-abandon-reopen")?,
            run: run.clone(),
            grant: grant_value.id.clone(),
            plan: plan_value.id.clone(),
            justification_evidence: justification,
        },
    )?;
    assert!(!abandonment.resources.is_empty());
    assert_eq!(
        reopened
            .attempt(&first)?
            .ok_or("completed attempt missing")?
            .state,
        AttemptState::Completed
    );
    let mut successor_grant = grant()?;
    successor_grant.id = id("grant-halted-reopen-successor")?;
    reopened.save_grant(&successor_grant)?;
    let mut successor_plan = plan("target-a")?;
    successor_plan.id = id("plan-halted-reopen-successor")?;
    successor_plan.review_digest = successor_plan.digest()?;
    reopened.save_plan(&successor_plan)?;
    let successor = AttemptRecord {
        id: id("attempt-halted-reopen-successor")?,
        request: id("request-halted-reopen-successor")?,
        grant: successor_grant.id.clone(),
        plan: successor_plan.id.clone(),
        operation_index: 0,
        plan_digest: successor_plan.digest()?,
        reserved: Budget::try_new(2, 2, 200)?,
        profile: profile_value.id.clone(),
        profile_digest: profile_value.digest()?,
        leased_resources: profile_value.physical_resources(),
        evidence_challenge: digest(b"halted-reopen-successor-challenge"),
        evidence_ordinal: 0,
        state: AttemptState::Intent,
        receipt: None,
        created_at: "2099-01-01T00:00:00Z".to_owned(),
        updated_at: "2099-01-01T00:00:00Z".to_owned(),
    };
    assert!(matches!(
        reopened.reserve(
            &successor,
            &AdmissionSnapshot {
                agent: id("agent-a")?,
                profile: profile_value,
                plan: successor_plan,
            },
        )?,
        cheirismos::store::ReservationOutcome::Reserved(_)
    ));
    Ok(())
}
