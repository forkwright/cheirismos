//! Closed, authenticated service requests that delegate authority to the supervisor.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::domain::{
    ArtifactDigest, AttemptId, CaseFact, CaseId, CommissionedProfile, Grant, GrantId, Observation,
    PlanId, PlanProposal, Principal, PrincipalRole,
};
use crate::evidence::{ArtifactStore, EvidenceError, EvidenceSource};
use crate::firmware::{
    ByteRange, CandidateEvidence, ImagePatch, Sha256Digest, build_candidate, compare_images,
    inspect_image,
};
use crate::supervisor::{
    Backend, PlanAdmissionRequest, PlanTicket, RecoveryTakeoverRequest, Supervisor, SupervisorError,
};

const MAX_EVIDENCE_FETCH_BYTES: usize = 1024 * 1024;

/// An optional read-only inventory and commissioning observation source.
///
/// This is deliberately separate from `Backend`: core dispatch remains the
/// only route that can operate an instrument under a grant.
pub trait InstrumentInspector: Send + Sync {
    /// Returns a current operator-only observation without performing an effect.
    fn inspect(&self, instrument: &crate::domain::InstrumentId) -> Result<Observation, String>;

    /// Returns configured capability facts without opening any device.
    fn inventory(&self) -> serde_json::Value;
}

/// The authenticated request families exposed by the local daemon.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "family", content = "request", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum ServiceRequest {
    /// Case facts and their evidence references.
    Case(CaseRequest),
    /// Artifact publication by bytes supplied by the client.
    Evidence(EvidenceRequest),
    /// Operator-only read-only device discovery.
    Instrument(InstrumentRequest),
    /// Proposal, independent review, and durable experiment execution.
    Experiment(ExperimentRequest),
    /// Durable attempt status and reconciliation.
    Transaction(TransactionRequest),
    /// Operator authority over profiles and grants.
    Authority(AuthorityRequest),
    /// Offline firmware evidence over existing content-addressed artifacts.
    Firmware(FirmwareRequest),
    /// Service status and configured inventory.
    System(SystemRequest),
}

/// A case request with no caller-selected principal.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CaseRequest {
    /// Append a typed fact to a case.
    Append { case: CaseId, fact: CaseFact },
    /// Return the durable facts recorded for a case.
    Get { case: CaseId },
}

/// An evidence request whose artifact bytes arrive from the client.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum EvidenceRequest {
    /// Publish base64-encoded bytes as case evidence.
    Import { case: CaseId, bytes_base64: String },
    /// Read a bounded base64 segment from an existing artifact.
    Fetch {
        artifact: ArtifactDigest,
        offset: u64,
        max_bytes: u32,
    },
}

/// Read-only operator device discovery requests.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum InstrumentRequest {
    /// Obtain a fresh commissioning observation for one configured instrument.
    Inspect {
        instrument: crate::domain::InstrumentId,
    },
}

/// Proposal, review, and execution requests.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ExperimentRequest {
    /// Persist an agent-owned candidate plan awaiting independent review.
    Propose { proposal: PlanProposal },
    /// Have the authenticated reviewer approve the exact proposal digest they observed.
    Review {
        plan: PlanId,
        expected_digest: ArtifactDigest,
    },
    /// Admit a complete reviewed plan before a service-owned task can execute it.
    Execute {
        grant: GrantId,
        plan: PlanId,
        run: crate::domain::RequestId,
        first_attempt: AttemptId,
    },
    /// Resume an interrupted admitted run from its first durable pending step.
    Resume { run: crate::domain::RequestId },
    /// Return one durable attempt record.
    Attempt { attempt: AttemptId },
}

/// Status and reconciliation requests over durable attempts.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum TransactionRequest {
    /// Return one durable attempt record.
    Get { attempt: AttemptId },
    /// Return immutable reconciliation witnesses for one attempt.
    ReconciliationHistory { attempt: AttemptId },
    /// Reconcile only a durable unknown attempt with fresh backend evidence.
    Reconcile {
        /// Durable idempotency key for this reconciliation request.
        request: crate::domain::RequestId,
        /// Unknown attempt to reconcile from fresh evidence.
        attempt: AttemptId,
    },
    /// Atomically transfer unresolved physical leases into a reviewed recovery run.
    RecoveryTakeover { recovery: RecoveryTakeoverRequest },
}

/// Operator-only profile and grant administration.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum AuthorityRequest {
    /// Record a qualified commissioned profile.
    Commission { profile: CommissionedProfile },
    /// Issue a bounded grant to an existing configured agent principal.
    IssueGrant {
        agent: crate::domain::PrincipalId,
        grant: Grant,
    },
    /// Revoke one existing grant.
    RevokeGrant { grant: GrantId },
}

/// Offline byte-only firmware operations over existing artifact digests.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FirmwareRequest {
    /// Inspect a single existing artifact without parsing a platform-specific format.
    Inspect { artifact: ArtifactDigest },
    /// Compare two equal-sized existing artifacts.
    Diff {
        left: ArtifactDigest,
        right: ArtifactDigest,
        max_ranges: usize,
    },
    /// Build and publish a candidate artifact under a supplied case.
    BuildCandidate {
        case: CaseId,
        original: ArtifactDigest,
        patches: Vec<ImagePatch>,
        protected_ranges: Vec<ByteRange>,
    },
}

/// Requests that return service-level facts without opening an instrument.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SystemRequest {
    /// Return the configured inventory summary.
    Status {},
}

/// A compact JSON-safe service response that never returns token material.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceResponse {
    /// Durable or reporting status, never a speculative completion assertion.
    pub status: ResponseStatus,
    /// Typed result rendered as JSON for the selected request family.
    pub result: serde_json::Value,
}

/// Response state that distinguishes durable admission from completion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResponseStatus {
    /// A read-only or durable report was produced.
    Reported,
    /// A physical operation has a durable intent and continues independently.
    Admitted,
    /// The request matched an existing durable attempt.
    Existing,
}

/// Errors while mapping authenticated requests to core authority operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ApiError {
    /// The authenticated role cannot perform this request.
    #[snafu(display("authenticated principal is not permitted to perform this request"))]
    Permission,
    #[snafu(display("artifact fetch may return at most {MAX_EVIDENCE_FETCH_BYTES} bytes"))]
    EvidenceFetchTooLarge,
    #[snafu(display("artifact fetch offset or range is outside the artifact"))]
    EvidenceFetchOutOfRange,
    #[snafu(display("grant recipient is not a configured local principal"))]
    UnknownPrincipal,
    #[snafu(display("recovery grant recipient is not a configured agent principal"))]
    RecoveryAgentUnavailable,
    #[snafu(display("service blocking task failed: {source}"))]
    Task { source: tokio::task::JoinError },
    /// No read-only instrument inspector was configured for this daemon.
    #[snafu(display("instrument inspection is unavailable for this service"))]
    InspectionUnavailable,
    /// Read-only instrument inspection failed.
    #[snafu(display("instrument inspection failed: {message}"))]
    Inspection { message: String },
    /// Base64 evidence input was malformed.
    #[snafu(display("artifact import bytes are not valid base64: {source}"))]
    Base64 { source: base64::DecodeError },
    /// Artifact publication or retrieval failed.
    #[snafu(display("artifact operation failed: {source}"))]
    Evidence { source: EvidenceError },
    /// Firmware-byte processing failed.
    #[snafu(display("firmware operation failed: {source}"))]
    Firmware {
        source: crate::firmware::FirmwareError,
    },
    /// Core admission or authority handling failed.
    #[snafu(display("supervisor operation failed: {source}"))]
    Supervisor { source: SupervisorError },
    /// A report could not be rendered as JSON.
    #[snafu(display("service response serialization failed: {source}"))]
    Json { source: serde_json::Error },
}

/// The authenticated API facade, with a service-owned backend lifetime.
#[derive(Clone)]
pub struct ServiceApi {
    supervisor: Arc<Supervisor>,
    artifacts: Arc<ArtifactStore>,
    backend: Arc<dyn Backend>,
    inspector: Option<Arc<dyn InstrumentInspector>>,
    principals: BTreeMap<crate::domain::PrincipalId, Principal>,
}

impl ServiceApi {
    /// Creates an API facade around the authoritative supervisor and backend.
    #[must_use]
    pub fn new(
        supervisor: Arc<Supervisor>,
        artifacts: Arc<ArtifactStore>,
        backend: Arc<dyn Backend>,
        inspector: Option<Arc<dyn InstrumentInspector>>,
        principals: BTreeMap<crate::domain::PrincipalId, Principal>,
    ) -> Self {
        Self {
            supervisor,
            artifacts,
            backend,
            inspector,
            principals,
        }
    }

    /// Handles one request using only the principal authenticated by the server.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for malformed evidence, unavailable inspection,
    /// authorization failure, or a core authority refusal.
    pub async fn handle(
        &self,
        principal: Principal,
        request: ServiceRequest,
    ) -> Result<ServiceResponse, ApiError> {
        match request {
            ServiceRequest::Case(request) => self.handle_case(&principal, request),
            ServiceRequest::Evidence(request) => self.handle_evidence(request),
            ServiceRequest::Instrument(request) => {
                self.handle_instrument(&principal, request).await
            }
            ServiceRequest::Experiment(request) => self.handle_experiment(principal, request),
            ServiceRequest::Transaction(request) => {
                self.handle_transaction(&principal, request).await
            }
            ServiceRequest::Authority(request) => self.handle_authority(&principal, request),
            ServiceRequest::Firmware(request) => self.handle_firmware(request),
            ServiceRequest::System(SystemRequest::Status {}) => Ok(self.report(self.inventory())?),
        }
    }

    fn handle_case(
        &self,
        principal: &Principal,
        request: CaseRequest,
    ) -> Result<ServiceResponse, ApiError> {
        match request {
            CaseRequest::Append { case, fact } => {
                if matches!(fact, CaseFact::Observation { .. }) {
                    require_operator(principal)?;
                }
                self.supervisor
                    .append_case_fact(&case, &fact)
                    .map_err(|source| ApiError::Supervisor { source })?;
                self.report(serde_json::json!({ "case": case }))
            }
            CaseRequest::Get { case } => self
                .supervisor
                .case(&case)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|record| self.report_value(record)),
        }
    }

    fn handle_evidence(&self, request: EvidenceRequest) -> Result<ServiceResponse, ApiError> {
        match request {
            EvidenceRequest::Import { case, bytes_base64 } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(bytes_base64)
                    .map_err(|source| ApiError::Base64 { source })?;
                let digest = self
                    .artifacts
                    .publish(&bytes, EvidenceSource::Case(case))
                    .map_err(|source| ApiError::Evidence { source })?;
                self.report(serde_json::json!({ "artifact": digest }))
            }
            EvidenceRequest::Fetch {
                artifact,
                offset,
                max_bytes,
            } => {
                let max_bytes =
                    usize::try_from(max_bytes).map_err(|_| ApiError::EvidenceFetchTooLarge)?;
                if max_bytes > MAX_EVIDENCE_FETCH_BYTES {
                    return Err(ApiError::EvidenceFetchTooLarge);
                }
                let bytes = self.artifact_bytes(&artifact)?;
                let offset =
                    usize::try_from(offset).map_err(|_| ApiError::EvidenceFetchOutOfRange)?;
                let available = bytes
                    .len()
                    .checked_sub(offset)
                    .ok_or(ApiError::EvidenceFetchOutOfRange)?;
                let length = available.min(max_bytes);
                let end = offset
                    .checked_add(length)
                    .ok_or(ApiError::EvidenceFetchOutOfRange)?;
                let segment = bytes
                    .get(offset..end)
                    .ok_or(ApiError::EvidenceFetchOutOfRange)?;
                self.report(serde_json::json!({
                    "artifact": artifact,
                    "offset": offset,
                    "bytes_base64": base64::engine::general_purpose::STANDARD.encode(segment),
                    "complete": end == bytes.len(),
                }))
            }
        }
    }

    async fn handle_instrument(
        &self,
        principal: &Principal,
        request: InstrumentRequest,
    ) -> Result<ServiceResponse, ApiError> {
        require_operator(principal)?;
        let inspector = self
            .inspector
            .as_ref()
            .ok_or(ApiError::InspectionUnavailable)?;
        match request {
            InstrumentRequest::Inspect { instrument } => {
                let inspector = Arc::clone(inspector);
                let observation =
                    tokio::task::spawn_blocking(move || inspector.inspect(&instrument))
                        .await
                        .map_err(|source| ApiError::Task { source })?
                        .map_err(|message| ApiError::Inspection { message })?;
                self.report_value(observation)
            }
        }
    }

    fn handle_experiment(
        &self,
        principal: Principal,
        request: ExperimentRequest,
    ) -> Result<ServiceResponse, ApiError> {
        match request {
            ExperimentRequest::Propose { proposal } => self
                .supervisor
                .propose_plan(&principal, proposal)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|proposal| self.report_value(proposal)),
            ExperimentRequest::Review {
                plan,
                expected_digest,
            } => self
                .supervisor
                .review_proposal(&principal, &plan, &expected_digest)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|plan| self.report_value(plan)),
            ExperimentRequest::Execute {
                grant,
                plan,
                run,
                first_attempt,
            } => self.execute_detached(principal, grant, plan, run, first_attempt),
            ExperimentRequest::Resume { run } => self.resume_detached(principal, run),
            ExperimentRequest::Attempt { attempt } => self.attempt_response(&attempt),
        }
    }

    /// Admits the whole reviewed plan before returning and owns its execution task.
    ///
    /// Admission reserves all plan resources before the first backend call. The
    /// task deliberately has no connection-owned cancellation token, so a client
    /// or MCP transport disconnect cannot interrupt admitted physical work.
    fn execute_detached(
        &self,
        principal: Principal,
        grant: GrantId,
        plan: PlanId,
        run: crate::domain::RequestId,
        first_attempt: AttemptId,
    ) -> Result<ServiceResponse, ApiError> {
        let ticket = self
            .supervisor
            .admit_plan(
                &principal,
                PlanAdmissionRequest {
                    run,
                    first_attempt: first_attempt.clone(),
                    grant,
                    plan,
                },
                self.backend.as_ref(),
            )
            .map_err(|source| ApiError::Supervisor { source })?;
        self.spawn_plan_execution(principal, ticket);
        Ok(ServiceResponse {
            status: ResponseStatus::Admitted,
            result: serde_json::json!({ "attempt": first_attempt }),
        })
    }

    /// Restarts only a durable admitted run that core proves is safe to continue.
    fn resume_detached(
        &self,
        principal: Principal,
        run: crate::domain::RequestId,
    ) -> Result<ServiceResponse, ApiError> {
        let ticket = self
            .supervisor
            .resume_plan(&principal, &run)
            .map_err(|source| ApiError::Supervisor { source })?;
        self.spawn_plan_execution(principal, ticket);
        Ok(ServiceResponse {
            status: ResponseStatus::Admitted,
            result: serde_json::json!({ "run": run, "resumed": true }),
        })
    }

    /// Keeps the backend call owned by a detached service task after admission.
    fn spawn_plan_execution(&self, principal: Principal, ticket: PlanTicket) {
        let supervisor = Arc::clone(&self.supervisor);
        let backend = Arc::clone(&self.backend);
        let _execution = tokio::task::spawn_blocking(move || {
            let mut ticket = ticket;
            loop {
                match supervisor.execute_next(&principal, ticket, backend.as_ref()) {
                    Ok(progress) => match progress.next {
                        Some(next) => ticket = next,
                        None => break,
                    },
                    Err(error) => {
                        tracing::error!(error = %error, "admitted plan execution stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn handle_transaction(
        &self,
        principal: &Principal,
        request: TransactionRequest,
    ) -> Result<ServiceResponse, ApiError> {
        match request {
            TransactionRequest::Get { attempt } => self.attempt_response(&attempt),
            TransactionRequest::ReconciliationHistory { attempt } => self
                .supervisor
                .reconciliation_history(&attempt)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|history| self.report_value(history)),
            TransactionRequest::Reconcile { request, attempt } => {
                let supervisor = Arc::clone(&self.supervisor);
                let backend = Arc::clone(&self.backend);
                let principal = principal.clone();
                let record = tokio::task::spawn_blocking(move || {
                    supervisor.reconcile(&principal, &attempt, &request, backend.as_ref())
                })
                .await
                .map_err(|source| ApiError::Task { source })?
                .map_err(|source| ApiError::Supervisor { source })?;
                self.report_value(record)
            }
            TransactionRequest::RecoveryTakeover { recovery } => {
                let run = recovery.run.clone();
                let grant = self
                    .supervisor
                    .grant(recovery.grant.as_str())
                    .map_err(|source| ApiError::Supervisor { source })?
                    .ok_or(ApiError::RecoveryAgentUnavailable)?;
                let agent = self
                    .principals
                    .get(&grant.agent)
                    .filter(|candidate| candidate.role == PrincipalRole::Agent)
                    .cloned()
                    .ok_or(ApiError::RecoveryAgentUnavailable)?;
                let supervisor = Arc::clone(&self.supervisor);
                let backend = Arc::clone(&self.backend);
                let operator = principal.clone();
                let ticket = tokio::task::spawn_blocking(move || {
                    supervisor.takeover_recovery(&operator, recovery, backend.as_ref())
                })
                .await
                .map_err(|source| ApiError::Task { source })?
                .map_err(|source| ApiError::Supervisor { source })?;
                self.spawn_plan_execution(agent, ticket);
                Ok(ServiceResponse {
                    status: ResponseStatus::Admitted,
                    result: serde_json::json!({ "run": run, "recovery": true }),
                })
            }
        }
    }

    fn handle_authority(
        &self,
        principal: &Principal,
        request: AuthorityRequest,
    ) -> Result<ServiceResponse, ApiError> {
        match request {
            AuthorityRequest::Commission { profile } => self
                .supervisor
                .commission(principal, profile)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|()| self.report(serde_json::json!({ "commissioned": true }))),
            AuthorityRequest::IssueGrant { agent, grant } => self
                .principals
                .get(&agent)
                .ok_or(ApiError::UnknownPrincipal)
                .and_then(|agent| {
                    self.supervisor
                        .issue_grant(principal, agent, grant)
                        .map_err(|source| ApiError::Supervisor { source })
                })
                .and_then(|()| self.report(serde_json::json!({ "issued": true }))),
            AuthorityRequest::RevokeGrant { grant } => self
                .supervisor
                .revoke_grant(principal, &grant)
                .map_err(|source| ApiError::Supervisor { source })
                .and_then(|()| self.report(serde_json::json!({ "revoked": true }))),
        }
    }

    fn handle_firmware(&self, request: FirmwareRequest) -> Result<ServiceResponse, ApiError> {
        match request {
            FirmwareRequest::Inspect { artifact } => {
                let bytes = self.artifact_bytes(&artifact)?;
                let inspection =
                    inspect_image(&bytes).map_err(|source| ApiError::Firmware { source })?;
                self.report_value(inspection)
            }
            FirmwareRequest::Diff {
                left,
                right,
                max_ranges,
            } => {
                let left_bytes = self.artifact_bytes(&left)?;
                let right_bytes = self.artifact_bytes(&right)?;
                let comparison = compare_images(&left_bytes, &right_bytes, max_ranges)
                    .map_err(|source| ApiError::Firmware { source })?;
                self.report_value(comparison)
            }
            FirmwareRequest::BuildCandidate {
                case,
                original,
                patches,
                protected_ranges,
            } => self.build_firmware_candidate(case, original, patches, protected_ranges),
        }
    }

    fn build_firmware_candidate(
        &self,
        case: CaseId,
        original: ArtifactDigest,
        patches: Vec<ImagePatch>,
        protected_ranges: Vec<ByteRange>,
    ) -> Result<ServiceResponse, ApiError> {
        let bytes = self.artifact_bytes(&original)?;
        let expected = Sha256Digest::try_from(original.as_str())
            .map_err(|source| ApiError::Firmware { source })?;
        let candidate = build_candidate(&bytes, &expected, &patches, &protected_ranges)
            .map_err(|source| ApiError::Firmware { source })?;
        let artifact = self
            .artifacts
            .publish(candidate.as_bytes(), EvidenceSource::Case(case))
            .map_err(|source| ApiError::Evidence { source })?;
        let evidence = candidate.evidence().clone();
        self.report_value(FirmwareCandidateResponse { artifact, evidence })
    }

    fn attempt_response(&self, attempt: &AttemptId) -> Result<ServiceResponse, ApiError> {
        let record = self
            .supervisor
            .attempt(attempt)
            .map_err(|source| ApiError::Supervisor { source })?;
        self.report_value(record)
    }

    fn artifact_bytes(&self, digest: &ArtifactDigest) -> Result<Vec<u8>, ApiError> {
        self.artifacts
            .read(digest)
            .map(|artifact| artifact.as_bytes().to_vec())
            .map_err(|source| ApiError::Evidence { source })
    }

    fn inventory(&self) -> serde_json::Value {
        self.inspector.as_ref().map_or_else(
            || serde_json::json!({ "instruments": [] }),
            |inspector| inspector.inventory(),
        )
    }

    fn report(&self, result: serde_json::Value) -> Result<ServiceResponse, ApiError> {
        Ok(ServiceResponse {
            status: ResponseStatus::Reported,
            result,
        })
    }

    fn report_value<T: Serialize>(&self, result: T) -> Result<ServiceResponse, ApiError> {
        self.report(serde_json::to_value(result).map_err(|source| ApiError::Json { source })?)
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FirmwareCandidateResponse {
    artifact: ArtifactDigest,
    evidence: CandidateEvidence,
}

fn require_operator(principal: &Principal) -> Result<(), ApiError> {
    if matches!(
        principal.role,
        PrincipalRole::Operator | PrincipalRole::Admin
    ) {
        Ok(())
    } else {
        Err(ApiError::Permission)
    }
}
