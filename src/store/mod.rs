//! SQLite persistence for authority, plans, attempts, and case facts.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use jiff::Timestamp;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use snafu::Snafu;

use crate::domain::{
    AttemptId, AttemptRecord, AttemptState, Budget, CaseFact, CaseId, CaseRecord,
    CommissionedProfile, EffectPermission, Grant, GrantId, HaltedRunAbandonmentRecord,
    OperationReceipt, PlanId, PlanProposal, PlanRun, PrincipalId, ReconciliationRecord,
    ReconciliationState, RecoveryTakeoverRecord, RequestId, ReviewedPlan,
};

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum StoreError {
    #[snafu(display("sqlite failure: {source}"))]
    Sqlite { source: rusqlite::Error },

    #[snafu(display("store I/O failure: {source}"))]
    Io { source: std::io::Error },

    #[snafu(display("serialization failure: {source}"))]
    Json { source: serde_json::Error },

    #[snafu(display("store mutex was poisoned"))]
    Poisoned,

    #[snafu(display("missing {kind}: {id}"))]
    Missing { kind: &'static str, id: String },

    #[snafu(display("grant {id} is revoked"))]
    Revoked { id: GrantId },

    #[snafu(display("grant {id} has expired"))]
    Expired { id: GrantId },

    #[snafu(display("grant {id} cannot reserve the requested budget"))]
    BudgetExhausted { id: GrantId },

    #[snafu(display("attempt {id} is not awaiting dispatch"))]
    NotDispatchable { id: AttemptId },

    #[snafu(display("plan steps must execute in order"))]
    OutOfOrder,

    #[snafu(display("profile {profile} is leased by another active experiment"))]
    LeaseBusy { profile: String },

    #[snafu(display("database is already owned by another live supervisor: {}", path.display()))]
    AlreadyOpen { path: PathBuf },

    #[snafu(display("immutable record {kind} conflicts at id {id}"))]
    Conflict { kind: &'static str, id: String },

    #[snafu(display("reviewer did not review proposal {id} at the supplied digest"))]
    ReviewDigestMismatch { id: PlanId },

    #[snafu(display("database integrity check failed: {message}"))]
    Integrity { message: String },

    #[snafu(display("{field} exceeds SQLite's signed 64-bit range: {value}"))]
    IntegerOutOfRange { field: &'static str, value: u64 },

    #[snafu(display("stored {field} is negative: {value}"))]
    NegativeStoredInteger { field: &'static str, value: i64 },
}

#[derive(Debug, Clone)]
pub struct Reservation {
    pub attempt: AttemptRecord,
}

#[derive(Debug, Clone)]
pub struct AdmissionSnapshot {
    pub agent: PrincipalId,
    pub profile: CommissionedProfile,
    pub plan: ReviewedPlan,
}

#[derive(Debug, Clone)]
pub struct ClaimedDispatch {
    pub attempt: AttemptRecord,
    pub grant: Grant,
    pub profile: CommissionedProfile,
    pub plan: ReviewedPlan,
}

#[derive(Debug, Clone)]
pub struct ClaimedReconciliation {
    pub record: ReconciliationRecord,
    pub dispatch: ClaimedDispatch,
}

#[derive(Debug, Clone)]
pub enum ReconciliationClaim {
    Existing(Box<ReconciliationRecord>),
    Claimed(Box<ClaimedReconciliation>),
}

#[derive(Debug, Clone)]
pub enum ReservationOutcome {
    Existing(AttemptRecord),
    Reserved(Reservation),
}

#[derive(Debug)]
pub struct SqliteStore {
    connection: Mutex<Connection>,
    _journal_lock: Option<File>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let journal_lock = acquire_journal_lock(path)?;
        let connection = Connection::open(path).map_err(|source| StoreError::Sqlite { source })?;
        Self::from_connection(connection, Some(journal_lock))
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let connection =
            Connection::open_in_memory().map_err(|source| StoreError::Sqlite { source })?;
        Self::from_connection(connection, None)
    }

    pub fn save_profile(&self, profile: &CommissionedProfile) -> Result<(), StoreError> {
        self.save_immutable("profiles", profile.id.as_str(), profile)
    }

    pub fn profile(&self, id: &str) -> Result<Option<CommissionedProfile>, StoreError> {
        self.load_entity("profiles", id)
    }

    pub fn save_grant(&self, grant: &Grant) -> Result<(), StoreError> {
        self.save_immutable("grants", grant.id.as_str(), grant)
    }

    pub fn grant(&self, id: &str) -> Result<Option<Grant>, StoreError> {
        self.load_entity("grants", id)
    }

    pub fn revoke_grant(&self, id: &GrantId) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let json: String = transaction
            .query_row(
                "SELECT json FROM grants WHERE id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| StoreError::Sqlite { source })?
            .ok_or_else(|| StoreError::Missing {
                kind: "grant",
                id: id.to_string(),
            })?;
        let mut grant: Grant = decode(&json)?;
        grant.revoked = true;
        transaction
            .execute(
                "UPDATE grants SET json = ?2 WHERE id = ?1",
                params![id.as_str(), encode(&grant)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    pub fn save_plan(&self, plan: &ReviewedPlan) -> Result<(), StoreError> {
        let digest = plan
            .digest()
            .map_err(|source| StoreError::Json { source })?;
        let encoded = encode(plan)?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO plans (id, digest, json) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING",
            params![plan.id.as_str(), digest.as_str(), encoded],
        ).map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    pub fn save_proposal(&self, proposal: &PlanProposal) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let encoded = encode(proposal)?;
        let inserted = connection
            .execute(
                "INSERT INTO proposals (id, json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
                params![proposal.id.as_str(), encoded],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        if inserted == 1 {
            return Ok(());
        }
        let existing: PlanProposal =
            load_entity_from(&connection, "proposals", proposal.id.as_str())?.ok_or_else(|| {
                StoreError::Missing {
                    kind: "proposal",
                    id: proposal.id.to_string(),
                }
            })?;
        if existing
            .digest()
            .map_err(|source| StoreError::Json { source })?
            == proposal
                .digest()
                .map_err(|source| StoreError::Json { source })?
        {
            Ok(())
        } else {
            Err(StoreError::Conflict {
                kind: "proposal",
                id: proposal.id.to_string(),
            })
        }
    }

    pub fn proposal(&self, id: &str) -> Result<Option<PlanProposal>, StoreError> {
        self.load_entity("proposals", id)
    }

    pub fn delete_proposal(&self, id: &PlanId) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection
            .execute("DELETE FROM proposals WHERE id = ?1", [id.as_str()])
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    pub fn consume_reviewed_proposal(
        &self,
        proposal_id: &PlanId,
        expected_digest: &crate::domain::ArtifactDigest,
        plan: &ReviewedPlan,
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let json: String = transaction
            .query_row(
                "SELECT json FROM proposals WHERE id = ?1",
                [proposal_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| StoreError::Sqlite { source })?
            .ok_or_else(|| StoreError::Missing {
                kind: "proposal",
                id: proposal_id.to_string(),
            })?;
        let proposal: PlanProposal = decode(&json)?;
        if proposal
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != *expected_digest
        {
            return Err(StoreError::ReviewDigestMismatch {
                id: proposal_id.clone(),
            });
        }
        let plan_digest = plan
            .digest()
            .map_err(|source| StoreError::Json { source })?;
        let encoded = encode(plan)?;
        let inserted = transaction.execute("INSERT INTO plans (id, digest, json) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING", params![plan.id.as_str(), plan_digest.as_str(), encoded]).map_err(|source| StoreError::Sqlite { source })?;
        if inserted == 0 {
            let existing: ReviewedPlan = load_entity_from(&transaction, "plans", plan.id.as_str())?
                .ok_or_else(|| StoreError::Missing {
                    kind: "plan",
                    id: plan.id.to_string(),
                })?;
            if existing
                .digest()
                .map_err(|source| StoreError::Json { source })?
                != plan_digest
            {
                return Err(StoreError::Conflict {
                    kind: "plan",
                    id: plan.id.to_string(),
                });
            }
        }
        transaction
            .execute(
                "DELETE FROM proposals WHERE id = ?1",
                [proposal_id.as_str()],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    pub fn plan(&self, id: &str) -> Result<Option<ReviewedPlan>, StoreError> {
        self.load_entity("plans", id)
    }

    pub fn create_run(&self, run: &PlanRun) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let inserted = connection
            .execute(
                "INSERT INTO runs (id, json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
                params![run.id.as_str(), encode(run)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        if inserted == 1 {
            return Ok(());
        }
        let existing: PlanRun = load_entity_from(&connection, "runs", run.id.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "run",
                id: run.id.to_string(),
            })?;
        if existing.agent == run.agent
            && existing.grant == run.grant
            && existing.plan == run.plan
            && existing.steps == run.steps
        {
            Ok(())
        } else {
            Err(StoreError::Conflict {
                kind: "run",
                id: run.id.to_string(),
            })
        }
    }

    pub fn run(&self, id: &RequestId) -> Result<Option<PlanRun>, StoreError> {
        self.load_entity("runs", id.as_str())
    }

    /// Returns the durable abandonment record which permanently closes this
    /// run, if an operator released its halted lease.
    pub fn halted_run_abandonment(
        &self,
        run: &RequestId,
    ) -> Result<Option<HaltedRunAbandonmentRecord>, StoreError> {
        let connection = self.lock()?;
        load_halted_run_abandonment_by_run(&connection, run)
    }

    /// Loads an abandonment by its immutable idempotency key.
    pub fn halted_run_abandonment_request(
        &self,
        request: &RequestId,
    ) -> Result<Option<HaltedRunAbandonmentRecord>, StoreError> {
        let connection = self.lock()?;
        load_halted_run_abandonment_by_request(&connection, request)
    }

    /// Tests whether this grant/plan authority pair was explicitly closed.
    /// This is checked by admission as well as by the claim transaction.
    pub fn is_halted_pair(&self, grant: &GrantId, plan: &PlanId) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        halted_pair_exists(&connection, grant, plan)
    }

    /// A retired source pair already transferred its lease into a successor
    /// recovery run and can never resume, reserve, or dispatch again.
    pub fn is_recovery_source_retired(
        &self,
        grant: &GrantId,
        plan: &PlanId,
    ) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        recovery_source_retired(&connection, grant, plan)
    }

    /// Snapshot the currently held canonical lease keys for an abandonment
    /// record. The write transaction compares this set again before release.
    pub fn halted_pair_resources(
        &self,
        grant: &GrantId,
        plan: &PlanId,
    ) -> Result<std::collections::BTreeSet<String>, StoreError> {
        let connection = self.lock()?;
        lease_keys_for_pair(&connection, grant, plan)
    }

    /// Persist an operator-authorized abandonment and release only leases
    /// which are still owned by the named grant/plan pair. Completed receipts
    /// and spent grant budget remain immutable.
    pub fn abandon_halted_run(
        &self,
        proposed: &HaltedRunAbandonmentRecord,
    ) -> Result<HaltedRunAbandonmentRecord, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;

        if let Some(existing) =
            load_halted_run_abandonment_by_request(&transaction, &proposed.request)?
        {
            if same_halted_run_abandonment(&existing, proposed) {
                transaction
                    .commit()
                    .map_err(|source| StoreError::Sqlite { source })?;
                return Ok(existing);
            }
            return Err(StoreError::Conflict {
                kind: "halted run abandonment",
                id: proposed.request.to_string(),
            });
        }
        if let Some(existing) = load_halted_run_abandonment_by_run(&transaction, &proposed.run)? {
            return Err(StoreError::Conflict {
                kind: "halted run abandonment",
                id: existing.run.to_string(),
            });
        }
        if halted_pair_exists(&transaction, &proposed.grant, &proposed.plan)? {
            return Err(StoreError::Conflict {
                kind: "halted grant plan",
                id: proposed.plan.to_string(),
            });
        }
        if recovery_destination_exists(&transaction, &proposed.grant, &proposed.plan)? {
            return Err(StoreError::Conflict {
                kind: "recovery destination abandonment",
                id: proposed.plan.to_string(),
            });
        }

        let run: PlanRun = load_entity_from(&transaction, "runs", proposed.run.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "run",
                id: proposed.run.to_string(),
            })?;
        if run.grant != proposed.grant || run.plan != proposed.plan {
            return Err(StoreError::Conflict {
                kind: "run",
                id: proposed.run.to_string(),
            });
        }
        let mut statement = transaction
            .prepare("SELECT json FROM attempts WHERE grant_id = ?1 AND plan_id = ?2")
            .map_err(|source| StoreError::Sqlite { source })?;
        let attempts = statement
            .query_map(
                params![proposed.grant.as_str(), proposed.plan.as_str()],
                |row| row.get::<_, String>(0),
            )
            .map_err(|source| StoreError::Sqlite { source })?
            .map(|row| {
                row.map_err(|source| StoreError::Sqlite { source })
                    .and_then(|json| decode::<AttemptRecord>(&json))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        drop(statement);
        if attempts.is_empty() {
            return Err(StoreError::Missing {
                kind: "attempt for halted run",
                id: proposed.run.to_string(),
            });
        }
        for mut attempt in attempts {
            match attempt.state {
                AttemptState::Completed | AttemptState::Rejected => {}
                // This is a proven pre-effect state. Record a durable rejected
                // terminal before releasing the lease; no physical replay can
                // later claim the private dispatch ticket.
                AttemptState::Intent => {
                    attempt.state = AttemptState::Rejected;
                    attempt.receipt = Some(OperationReceipt::Rejected {
                        reason: "operator abandoned halted run before dispatch".to_owned(),
                    });
                    attempt.updated_at = Timestamp::now().to_string();
                    update_attempt(&transaction, &attempt)?;
                }
                AttemptState::Dispatched | AttemptState::Partial | AttemptState::Unknown => {
                    return Err(StoreError::NotDispatchable {
                        id: attempt.id.clone(),
                    });
                }
            }
        }
        let resources = lease_keys_for_pair(&transaction, &proposed.grant, &proposed.plan)?;
        if resources != proposed.resources {
            return Err(StoreError::Conflict {
                kind: "halted run resources",
                id: proposed.run.to_string(),
            });
        }
        for resource in &resources {
            transaction
                .execute(
                    "DELETE FROM plan_leases WHERE resource_key = ?1 AND grant_id = ?2 AND plan_id = ?3",
                    params![resource, proposed.grant.as_str(), proposed.plan.as_str()],
                )
                .map_err(|source| StoreError::Sqlite { source })?;
        }
        transaction
            .execute(
                "INSERT INTO halted_run_abandonments (request_id, run_id, grant_id, plan_id, json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![proposed.request.as_str(), proposed.run.as_str(), proposed.grant.as_str(), proposed.plan.as_str(), encode(proposed)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(proposed.clone())
    }

    pub fn advance_run(&self, id: &RequestId, cursor: usize) -> Result<(), StoreError> {
        let mut run = self.run(id)?.ok_or_else(|| StoreError::Missing {
            kind: "run",
            id: id.to_string(),
        })?;
        if run.cursor != cursor {
            return Err(StoreError::Conflict {
                kind: "run cursor",
                id: id.to_string(),
            });
        }
        run.cursor = run
            .cursor
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict {
                kind: "run cursor",
                id: id.to_string(),
            })?;
        self.save_entity("runs", id.as_str(), &run)
    }

    /// Restores a cursor that lagged a durably committed completed receipt.
    /// It never decreases a cursor or changes the immutable run identity.
    pub fn repair_run_cursor(&self, id: &RequestId) -> Result<PlanRun, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let mut run: PlanRun =
            load_entity_from(&transaction, "runs", id.as_str())?.ok_or_else(|| {
                StoreError::Missing {
                    kind: "run",
                    id: id.to_string(),
                }
            })?;
        let mut completed = 0;
        for (attempt, _) in &run.steps {
            match load_attempt(&transaction, attempt)? {
                Some(record) if record.state == AttemptState::Completed => completed += 1,
                _ => break,
            }
        }
        if completed > run.cursor {
            run.cursor = completed;
            transaction
                .execute(
                    "UPDATE runs SET json = ?2 WHERE id = ?1",
                    params![id.as_str(), encode(&run)?],
                )
                .map_err(|source| StoreError::Sqlite { source })?;
        }
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(run)
    }

    pub fn append_case_fact(&self, case: &CaseId, fact: &CaseFact) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO case_facts (case_id, ordinal, json) VALUES (?1, COALESCE((SELECT MAX(ordinal) + 1 FROM case_facts WHERE case_id = ?1), 0), ?2)",
            params![case.as_str(), encode(fact)?],
        ).map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    pub fn case(&self, id: &CaseId) -> Result<CaseRecord, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT json FROM case_facts WHERE case_id = ?1 ORDER BY ordinal ASC")
            .map_err(|source| StoreError::Sqlite { source })?;
        let rows = statement
            .query_map([id.as_str()], |row| row.get::<_, String>(0))
            .map_err(|source| StoreError::Sqlite { source })?;
        let facts = rows
            .map(|row| {
                row.map_err(|source| StoreError::Sqlite { source })
                    .and_then(|json| decode(&json))
            })
            .collect::<Result<Vec<CaseFact>, StoreError>>()?;
        Ok(CaseRecord {
            id: id.clone(),
            facts,
        })
    }

    pub fn reserve(
        &self,
        proposed: &AttemptRecord,
        snapshot: &AdmissionSnapshot,
    ) -> Result<ReservationOutcome, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        if let Some(existing) = load_attempt_by_request(&transaction, &proposed.request)? {
            if existing.id != proposed.id
                || existing.grant != proposed.grant
                || existing.plan != proposed.plan
                || existing.operation_index != proposed.operation_index
                || existing.plan_digest != proposed.plan_digest
            {
                return Err(StoreError::Conflict {
                    kind: "request",
                    id: proposed.request.to_string(),
                });
            }
            transaction
                .commit()
                .map_err(|source| StoreError::Sqlite { source })?;
            return Ok(ReservationOutcome::Existing(existing));
        }
        if halted_pair_exists(&transaction, &proposed.grant, &proposed.plan)? {
            return Err(StoreError::Conflict {
                kind: "halted grant plan",
                id: proposed.plan.to_string(),
            });
        }
        if recovery_source_retired(&transaction, &proposed.grant, &proposed.plan)? {
            return Err(StoreError::Conflict {
                kind: "retired recovery source",
                id: proposed.plan.to_string(),
            });
        }
        let grant_json: String = transaction
            .query_row(
                "SELECT json FROM grants WHERE id = ?1",
                [proposed.grant.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| StoreError::Sqlite { source })?
            .ok_or_else(|| StoreError::Missing {
                kind: "grant",
                id: proposed.grant.to_string(),
            })?;
        let mut grant: Grant = decode(&grant_json)?;
        if grant.agent != snapshot.agent || grant.profile != proposed.profile {
            return Err(StoreError::Conflict {
                kind: "grant",
                id: grant.id.to_string(),
            });
        }
        if grant.revoked {
            return Err(StoreError::Revoked { id: grant.id });
        }
        let expires_at =
            Timestamp::from_str(&grant.expires_at).map_err(|_| StoreError::Expired {
                id: grant.id.clone(),
            })?;
        if expires_at <= Timestamp::now() {
            return Err(StoreError::Expired { id: grant.id });
        }
        let profile: CommissionedProfile =
            load_entity_from(&transaction, "profiles", proposed.profile.as_str())?.ok_or_else(
                || StoreError::Missing {
                    kind: "profile",
                    id: proposed.profile.to_string(),
                },
            )?;
        if profile
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != proposed.profile_digest
            || profile
                .digest()
                .map_err(|source| StoreError::Json { source })?
                != snapshot
                    .profile
                    .digest()
                    .map_err(|source| StoreError::Json { source })?
        {
            return Err(StoreError::Conflict {
                kind: "profile",
                id: proposed.profile.to_string(),
            });
        }
        let plan: ReviewedPlan = load_entity_from(&transaction, "plans", proposed.plan.as_str())?
            .ok_or_else(|| StoreError::Missing {
            kind: "plan",
            id: proposed.plan.to_string(),
        })?;
        if plan
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != proposed.plan_digest
            || plan
                .digest()
                .map_err(|source| StoreError::Json { source })?
                != snapshot
                    .plan
                    .digest()
                    .map_err(|source| StoreError::Json { source })?
        {
            return Err(StoreError::Conflict {
                kind: "plan",
                id: proposed.plan.to_string(),
            });
        }
        let existing_steps = transaction
            .prepare("SELECT operation_index, state FROM attempts WHERE grant_id = ?1 AND plan_id = ?2 ORDER BY operation_index ASC")
            .map_err(|source| StoreError::Sqlite { source })?
            .query_map(params![proposed.grant.as_str(), proposed.plan.as_str()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))
            .map_err(|source| StoreError::Sqlite { source })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| StoreError::Sqlite { source })?;
        let expected = match existing_steps.last() {
            None => 0,
            Some((index, state)) if state == "completed" => {
                stored_index("attempt operation index", *index)? + 1
            }
            Some(_) => return Err(StoreError::OutOfOrder),
        };
        if proposed.operation_index != expected {
            return Err(StoreError::OutOfOrder);
        }
        if proposed.operation_index > 0 {
            let first: AttemptRecord = transaction.query_row("SELECT json FROM attempts WHERE grant_id = ?1 AND plan_id = ?2 AND operation_index = 0", params![proposed.grant.as_str(), proposed.plan.as_str()], |row| row.get::<_, String>(0)).map_err(|source| StoreError::Sqlite { source }).and_then(|json| decode(&json))?;
            if first.profile != proposed.profile
                || first.profile_digest != proposed.profile_digest
                || first.leased_resources != proposed.leased_resources
                || first.plan_digest != proposed.plan_digest
            {
                return Err(StoreError::Conflict {
                    kind: "run snapshot",
                    id: proposed.plan.to_string(),
                });
            }
        }
        for resource in &proposed.leased_resources {
            let key = resource.key();
            let lease = transaction
                .query_row(
                    "SELECT grant_id, plan_id FROM plan_leases WHERE resource_key = ?1",
                    [key.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|source| StoreError::Sqlite { source })?;
            match lease {
                Some((lease_grant, lease_plan))
                    if lease_grant == proposed.grant.as_str()
                        && lease_plan == proposed.plan.as_str() => {}
                Some(_) => return Err(StoreError::LeaseBusy { profile: key }),
                None => {
                    transaction.execute("INSERT INTO plan_leases (resource_key, grant_id, plan_id) VALUES (?1, ?2, ?3)", params![key, proposed.grant.as_str(), proposed.plan.as_str()]).map_err(|source| StoreError::Sqlite { source })?;
                }
            }
        }
        grant.remaining = grant
            .remaining
            .checked_sub(&proposed.reserved)
            .ok_or_else(|| StoreError::BudgetExhausted {
                id: grant.id.clone(),
            })?;
        transaction
            .execute(
                "UPDATE grants SET json = ?2 WHERE id = ?1",
                params![grant.id.as_str(), encode(&grant)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction.execute(
            "INSERT INTO attempts (id, request_id, grant_id, plan_id, operation_index, state, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![proposed.id.as_str(), proposed.request.as_str(), proposed.grant.as_str(), proposed.plan.as_str(), sqlite_index("attempt operation index", proposed.operation_index)?, state_text(proposed.state), encode(proposed)?],
        ).map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(ReservationOutcome::Reserved(Reservation {
            attempt: proposed.clone(),
        }))
    }

    /// Atomically records an authority-approved handoff, moves the existing
    /// lease, reserves the replacement plan, and creates its first durable
    /// intent. Source attempts are read-only evidence of the prior uncertainty.
    pub fn takeover_recovery(
        &self,
        proposed: &AttemptRecord,
        snapshot: &AdmissionSnapshot,
        run: &PlanRun,
        recovery: &RecoveryTakeoverRecord,
    ) -> Result<ReservationOutcome, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        if let Some(existing) = load_recovery_takeover(&transaction, &recovery.request)? {
            if !same_recovery_takeover(&existing, recovery) {
                return Err(StoreError::Conflict {
                    kind: "recovery takeover",
                    id: recovery.request.to_string(),
                });
            }
            let attempt =
                load_attempt(&transaction, &recovery.first_attempt)?.ok_or_else(|| {
                    StoreError::Missing {
                        kind: "recovery attempt",
                        id: recovery.first_attempt.to_string(),
                    }
                })?;
            transaction
                .commit()
                .map_err(|source| StoreError::Sqlite { source })?;
            return Ok(ReservationOutcome::Existing(attempt));
        }
        if let Some(existing) = load_attempt_by_request(&transaction, &proposed.request)? {
            return if existing.id == proposed.id
                && existing.grant == proposed.grant
                && existing.plan == proposed.plan
            {
                Ok(ReservationOutcome::Existing(existing))
            } else {
                Err(StoreError::Conflict {
                    kind: "request",
                    id: proposed.request.to_string(),
                })
            };
        }
        if halted_pair_exists(&transaction, &proposed.grant, &proposed.plan)?
            || recovery_source_retired(&transaction, &proposed.grant, &proposed.plan)?
        {
            return Err(StoreError::Conflict {
                kind: "closed recovery authority",
                id: proposed.plan.to_string(),
            });
        }
        let mut grant: Grant = load_entity_from(&transaction, "grants", proposed.grant.as_str())?
            .ok_or_else(|| StoreError::Missing {
            kind: "grant",
            id: proposed.grant.to_string(),
        })?;
        if grant.agent != snapshot.agent || grant.profile != proposed.profile {
            return Err(StoreError::Conflict {
                kind: "grant",
                id: grant.id.to_string(),
            });
        }
        if grant.revoked {
            return Err(StoreError::Revoked { id: grant.id });
        }
        let expires_at =
            Timestamp::from_str(&grant.expires_at).map_err(|_| StoreError::Expired {
                id: grant.id.clone(),
            })?;
        if expires_at <= Timestamp::now() {
            return Err(StoreError::Expired { id: grant.id });
        }
        let profile: CommissionedProfile =
            load_entity_from(&transaction, "profiles", proposed.profile.as_str())?.ok_or_else(
                || StoreError::Missing {
                    kind: "profile",
                    id: proposed.profile.to_string(),
                },
            )?;
        if profile
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != proposed.profile_digest
            || profile
                .digest()
                .map_err(|source| StoreError::Json { source })?
                != snapshot
                    .profile
                    .digest()
                    .map_err(|source| StoreError::Json { source })?
        {
            return Err(StoreError::Conflict {
                kind: "profile",
                id: proposed.profile.to_string(),
            });
        }
        let plan: ReviewedPlan = load_entity_from(&transaction, "plans", proposed.plan.as_str())?
            .ok_or_else(|| StoreError::Missing {
            kind: "plan",
            id: proposed.plan.to_string(),
        })?;
        if plan
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != proposed.plan_digest
            || plan
                .digest()
                .map_err(|source| StoreError::Json { source })?
                != snapshot
                    .plan
                    .digest()
                    .map_err(|source| StoreError::Json { source })?
        {
            return Err(StoreError::Conflict {
                kind: "plan",
                id: proposed.plan.to_string(),
            });
        }
        let mut old_owners = std::collections::BTreeSet::new();
        for source_id in &recovery.unresolved {
            let source =
                load_attempt(&transaction, source_id)?.ok_or_else(|| StoreError::Missing {
                    kind: "unresolved attempt",
                    id: source_id.to_string(),
                })?;
            let inherited_carrier =
                recovery_destination_exists(&transaction, &source.grant, &source.plan)?;
            if recovery_source_retired(&transaction, &source.grant, &source.plan)? {
                return Err(StoreError::Conflict {
                    kind: "retired recovery source",
                    id: source.plan.to_string(),
                });
            }
            if source_pair_has_dispatched(&transaction, &source.grant, &source.plan)? {
                return Err(StoreError::NotDispatchable { id: source.id });
            }
            if source_pair_has_active_reconciliation(&transaction, &source.grant, &source.plan)? {
                return Err(StoreError::Conflict {
                    kind: "active reconciliation",
                    id: source.plan.to_string(),
                });
            }
            let ordinary_uncertainty =
                matches!(source.state, AttemptState::Partial | AttemptState::Unknown);
            let inherited_pre_effect = inherited_carrier
                && matches!(
                    source.state,
                    AttemptState::Intent | AttemptState::Rejected | AttemptState::Completed
                );
            if !ordinary_uncertainty && !inherited_pre_effect {
                return Err(StoreError::NotDispatchable { id: source.id });
            }
            if source.leased_resources != proposed.leased_resources {
                return Err(StoreError::Conflict {
                    kind: "recovery resources",
                    id: source.id.to_string(),
                });
            }
            if load_active_reconciliation(&transaction, &source.id)?.is_some() {
                return Err(StoreError::Conflict {
                    kind: "active reconciliation",
                    id: source.id.to_string(),
                });
            }
            old_owners.insert((
                source.grant.as_str().to_owned(),
                source.plan.as_str().to_owned(),
            ));
        }
        for resource in &proposed.leased_resources {
            let key = resource.key();
            let owner = transaction
                .query_row(
                    "SELECT grant_id, plan_id FROM plan_leases WHERE resource_key = ?1",
                    [key.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|source| StoreError::Sqlite { source })?;
            let Some(owner) = owner else {
                return Err(StoreError::LeaseBusy { profile: key });
            };
            if !old_owners.contains(&owner) {
                return Err(StoreError::LeaseBusy { profile: key });
            }
            transaction.execute(
                "UPDATE plan_leases SET grant_id = ?2, plan_id = ?3 WHERE resource_key = ?1 AND grant_id = ?4 AND plan_id = ?5",
                params![resource.key(), proposed.grant.as_str(), proposed.plan.as_str(), owner.0, owner.1],
            ).map_err(|source| StoreError::Sqlite { source })?;
        }
        for (source_grant, source_plan) in &old_owners {
            transaction
                .execute(
                    "INSERT INTO recovery_source_retirements (grant_id, plan_id, takeover_request) VALUES (?1, ?2, ?3)",
                    params![source_grant, source_plan, recovery.request.as_str()],
                )
                .map_err(|source| StoreError::Sqlite { source })?;
        }
        grant.remaining = grant
            .remaining
            .checked_sub(&proposed.reserved)
            .ok_or_else(|| StoreError::BudgetExhausted {
                id: grant.id.clone(),
            })?;
        transaction
            .execute(
                "UPDATE grants SET json = ?2 WHERE id = ?1",
                params![grant.id.as_str(), encode(&grant)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction.execute("INSERT INTO attempts (id, request_id, grant_id, plan_id, operation_index, state, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![proposed.id.as_str(), proposed.request.as_str(), proposed.grant.as_str(), proposed.plan.as_str(), 0_i64, state_text(proposed.state), encode(proposed)?])
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .execute(
                "INSERT INTO runs (id, json) VALUES (?1, ?2)",
                params![run.id.as_str(), encode(run)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .execute(
                "INSERT INTO recovery_takeovers (request_id, json) VALUES (?1, ?2)",
                params![recovery.request.as_str(), encode(recovery)?],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(ReservationOutcome::Reserved(Reservation {
            attempt: proposed.clone(),
        }))
    }

    pub fn attempt_for_request(&self, id: &RequestId) -> Result<Option<AttemptRecord>, StoreError> {
        let connection = self.lock()?;
        load_attempt_by_request(&connection, id)
    }

    pub fn attempt(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, StoreError> {
        self.load_entity("attempts", id.as_str())
    }

    pub(crate) fn attempt_at_step(
        &self,
        grant: &GrantId,
        plan: &PlanId,
        index: usize,
    ) -> Result<Option<AttemptRecord>, StoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT json FROM attempts WHERE grant_id = ?1 AND plan_id = ?2 AND operation_index = ?3",
                params![grant.as_str(), plan.as_str(), sqlite_index("attempt operation index", index)?],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| StoreError::Sqlite { source })?
            .map(|json| decode(&json))
            .transpose()
    }

    pub fn claim_dispatch(
        &self,
        id: &AttemptId,
        agent: &PrincipalId,
    ) -> Result<ClaimedDispatch, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let mut attempt: AttemptRecord =
            load_attempt(&transaction, id)?.ok_or_else(|| StoreError::Missing {
                kind: "attempt",
                id: id.to_string(),
            })?;
        if attempt.state != AttemptState::Intent {
            return Err(StoreError::NotDispatchable { id: id.clone() });
        }
        if halted_pair_exists(&transaction, &attempt.grant, &attempt.plan)? {
            return Err(StoreError::NotDispatchable { id: id.clone() });
        }
        if recovery_source_retired(&transaction, &attempt.grant, &attempt.plan)? {
            return Err(StoreError::NotDispatchable { id: id.clone() });
        }
        let grant: Grant = load_entity_from(&transaction, "grants", attempt.grant.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "grant",
                id: attempt.grant.to_string(),
            })?;
        if grant.agent != *agent || grant.profile != attempt.profile {
            return Err(StoreError::Conflict {
                kind: "grant",
                id: grant.id.to_string(),
            });
        }
        if grant.revoked {
            return Err(StoreError::Revoked { id: grant.id });
        }
        let expires_at =
            Timestamp::from_str(&grant.expires_at).map_err(|_| StoreError::Expired {
                id: grant.id.clone(),
            })?;
        if expires_at <= Timestamp::now() {
            return Err(StoreError::Expired { id: grant.id });
        }
        let profile: CommissionedProfile =
            load_entity_from(&transaction, "profiles", attempt.profile.as_str())?.ok_or_else(
                || StoreError::Missing {
                    kind: "profile",
                    id: attempt.profile.to_string(),
                },
            )?;
        if profile
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != attempt.profile_digest
        {
            return Err(StoreError::Conflict {
                kind: "profile",
                id: attempt.profile.to_string(),
            });
        }
        let plan: ReviewedPlan = load_entity_from(&transaction, "plans", attempt.plan.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "plan",
                id: attempt.plan.to_string(),
            })?;
        if plan
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != attempt.plan_digest
        {
            return Err(StoreError::Conflict {
                kind: "plan",
                id: attempt.plan.to_string(),
            });
        }
        for resource in &attempt.leased_resources {
            let owner = transaction
                .query_row(
                    "SELECT grant_id, plan_id FROM plan_leases WHERE resource_key = ?1",
                    [resource.key()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|source| StoreError::Sqlite { source })?;
            if owner.as_ref().is_none_or(|(grant_id, plan_id)| {
                grant_id != attempt.grant.as_str() || plan_id != attempt.plan.as_str()
            }) {
                return Err(StoreError::LeaseBusy {
                    profile: resource.key(),
                });
            }
        }
        attempt.state = AttemptState::Dispatched;
        attempt.evidence_ordinal =
            attempt
                .evidence_ordinal
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict {
                    kind: "attempt",
                    id: attempt.id.to_string(),
                })?;
        attempt.evidence_challenge = crate::domain::ArtifactDigest::sha256(
            format!(
                "{}:{}:{}",
                attempt.id, attempt.updated_at, attempt.evidence_ordinal
            )
            .as_bytes(),
        );
        attempt.updated_at = Timestamp::now().to_string();
        update_attempt(&transaction, &attempt)?;
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(ClaimedDispatch {
            attempt,
            grant,
            profile,
            plan,
        })
    }

    pub fn record_receipt(
        &self,
        id: &AttemptId,
        receipt: OperationReceipt,
        release_lease: bool,
    ) -> Result<AttemptRecord, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let mut attempt: AttemptRecord =
            load_attempt(&transaction, id)?.ok_or_else(|| StoreError::Missing {
                kind: "attempt",
                id: id.to_string(),
            })?;
        if attempt.state != AttemptState::Dispatched {
            return Err(StoreError::NotDispatchable { id: id.clone() });
        }
        attempt.state = receipt.state();
        attempt.receipt = Some(receipt);
        attempt.updated_at = Timestamp::now().to_string();
        update_attempt(&transaction, &attempt)?;
        if release_lease
            && (!matches!(attempt.state, AttemptState::Rejected)
                || !recovery_destination_exists(&transaction, &attempt.grant, &attempt.plan)?)
        {
            release_leases(&transaction, &attempt)?;
        }
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(attempt)
    }

    pub fn reject_intent(
        &self,
        id: &AttemptId,
        reason: String,
    ) -> Result<AttemptRecord, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let mut attempt: AttemptRecord =
            load_attempt(&transaction, id)?.ok_or_else(|| StoreError::Missing {
                kind: "attempt",
                id: id.to_string(),
            })?;
        if attempt.state != AttemptState::Intent {
            return Err(StoreError::NotDispatchable { id: id.clone() });
        }
        attempt.state = AttemptState::Rejected;
        attempt.receipt = Some(OperationReceipt::Rejected { reason });
        attempt.updated_at = Timestamp::now().to_string();
        update_attempt(&transaction, &attempt)?;
        if !recovery_destination_exists(&transaction, &attempt.grant, &attempt.plan)? {
            release_leases(&transaction, &attempt)?;
        }
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(attempt)
    }

    /// Atomically creates the only active reconciliation witness for an uncertain
    /// attempt.  A retry with the same request id returns that witness and must
    /// not cause another backend call.
    pub fn claim_reconciliation(
        &self,
        attempt_id: &AttemptId,
        request: &RequestId,
        principal: &PrincipalId,
        configuration_budget: Option<&Budget>,
    ) -> Result<ReconciliationClaim, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        if let Some(existing) = load_reconciliation_by_request(&transaction, request)? {
            if existing.attempt != *attempt_id || existing.principal != *principal {
                return Err(StoreError::Conflict {
                    kind: "reconciliation request",
                    id: request.to_string(),
                });
            }
            transaction
                .commit()
                .map_err(|source| StoreError::Sqlite { source })?;
            return Ok(ReconciliationClaim::Existing(Box::new(existing)));
        }
        if let Some(existing) = load_active_reconciliation(&transaction, attempt_id)? {
            return Err(StoreError::Conflict {
                kind: "active reconciliation",
                id: existing.request.to_string(),
            });
        }
        let mut attempt =
            load_attempt(&transaction, attempt_id)?.ok_or_else(|| StoreError::Missing {
                kind: "attempt",
                id: attempt_id.to_string(),
            })?;
        if !matches!(attempt.state, AttemptState::Unknown | AttemptState::Partial) {
            return Err(StoreError::NotDispatchable { id: attempt.id });
        }
        let grant: Grant = load_entity_from(&transaction, "grants", attempt.grant.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "grant",
                id: attempt.grant.to_string(),
            })?;
        if grant.agent != *principal || grant.profile != attempt.profile {
            return Err(StoreError::Conflict {
                kind: "grant",
                id: grant.id.to_string(),
            });
        }
        if grant.revoked {
            return Err(StoreError::Revoked { id: grant.id });
        }
        let expires_at =
            Timestamp::from_str(&grant.expires_at).map_err(|_| StoreError::Expired {
                id: grant.id.clone(),
            })?;
        if expires_at <= Timestamp::now() {
            return Err(StoreError::Expired { id: grant.id });
        }
        let profile: CommissionedProfile =
            load_entity_from(&transaction, "profiles", attempt.profile.as_str())?.ok_or_else(
                || StoreError::Missing {
                    kind: "profile",
                    id: attempt.profile.to_string(),
                },
            )?;
        if profile
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != attempt.profile_digest
        {
            return Err(StoreError::Conflict {
                kind: "profile",
                id: attempt.profile.to_string(),
            });
        }
        let plan: ReviewedPlan = load_entity_from(&transaction, "plans", attempt.plan.as_str())?
            .ok_or_else(|| StoreError::Missing {
                kind: "plan",
                id: attempt.plan.to_string(),
            })?;
        if plan
            .digest()
            .map_err(|source| StoreError::Json { source })?
            != attempt.plan_digest
        {
            return Err(StoreError::Conflict {
                kind: "plan",
                id: attempt.plan.to_string(),
            });
        }
        if configuration_budget.is_some() {
            let operation = plan
                .operations
                .get(attempt.operation_index)
                .ok_or_else(|| StoreError::Conflict {
                    kind: "plan operation",
                    id: attempt.plan.to_string(),
                })?;
            let instrument =
                operation
                    .operation
                    .instrument()
                    .ok_or_else(|| StoreError::Conflict {
                        kind: "instrument configuration",
                        id: attempt.id.to_string(),
                    })?;
            let binding = profile
                .instrument(instrument)
                .ok_or_else(|| StoreError::Conflict {
                    kind: "instrument",
                    id: instrument.to_string(),
                })?;
            if !grant
                .effect_permissions
                .contains(&EffectPermission::InstrumentConfigure)
                || !binding
                    .qualified_effect_permissions
                    .contains(&EffectPermission::InstrumentConfigure)
            {
                return Err(StoreError::Conflict {
                    kind: "instrument configuration authority",
                    id: attempt.id.to_string(),
                });
            }
        }
        for resource in &attempt.leased_resources {
            let owner = transaction
                .query_row(
                    "SELECT grant_id, plan_id FROM plan_leases WHERE resource_key = ?1",
                    [resource.key()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|source| StoreError::Sqlite { source })?;
            if owner
                .as_ref()
                .is_none_or(|(g, p)| g != attempt.grant.as_str() || p != attempt.plan.as_str())
            {
                return Err(StoreError::LeaseBusy {
                    profile: resource.key(),
                });
            }
        }
        let mut updated_grant = grant.clone();
        if let Some(budget) = configuration_budget {
            updated_grant.remaining =
                updated_grant.remaining.checked_sub(budget).ok_or_else(|| {
                    StoreError::BudgetExhausted {
                        id: updated_grant.id.clone(),
                    }
                })?;
            transaction
                .execute(
                    "UPDATE grants SET json = ?2 WHERE id = ?1",
                    params![updated_grant.id.as_str(), encode(&updated_grant)?],
                )
                .map_err(|source| StoreError::Sqlite { source })?;
        }
        let stored_ordinal: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(ordinal) + 1, 0) FROM reconciliations WHERE attempt_id = ?1",
                [attempt.id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        let ordinal = stored_unsigned("reconciliation ordinal", stored_ordinal)?;
        let now = Timestamp::now().to_string();
        let challenge = crate::domain::ArtifactDigest::sha256(
            format!("reconcile:{}:{}:{}:{}", attempt.id, request, ordinal, now).as_bytes(),
        );
        let record = ReconciliationRecord {
            request: request.clone(),
            attempt: attempt.id.clone(),
            ordinal,
            challenge,
            principal: principal.clone(),
            state: ReconciliationState::Claimed,
            receipt: None,
            started_at: now,
            ended_at: None,
        };
        transaction.execute(
            "INSERT INTO reconciliations (request_id, attempt_id, ordinal, state, json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![record.request.as_str(), record.attempt.as_str(), sqlite_unsigned("reconciliation ordinal", ordinal)?, reconciliation_state_text(record.state), encode(&record)?],
        ).map_err(|source| StoreError::Sqlite { source })?;
        // A partial effect is unresolved; once a fresh investigation begins it is
        // represented as Unknown until evidence proves completion.
        if attempt.state == AttemptState::Partial {
            attempt.state = AttemptState::Unknown;
            attempt.updated_at = Timestamp::now().to_string();
            update_attempt(&transaction, &attempt)?;
        }
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(ReconciliationClaim::Claimed(Box::new(
            ClaimedReconciliation {
                record,
                dispatch: ClaimedDispatch {
                    attempt,
                    grant: updated_grant,
                    profile,
                    plan,
                },
            },
        )))
    }

    /// Finishes an append-only reconciliation witness.  The initial receipt is
    /// retained; only evidence proving completion advances the current state.
    pub fn finish_reconciliation(
        &self,
        request: &RequestId,
        receipt: Option<OperationReceipt>,
        completed: bool,
        release_lease: bool,
    ) -> Result<AttemptRecord, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| StoreError::Sqlite { source })?;
        let mut record =
            load_reconciliation_by_request(&transaction, request)?.ok_or_else(|| {
                StoreError::Missing {
                    kind: "reconciliation",
                    id: request.to_string(),
                }
            })?;
        if record.state != ReconciliationState::Claimed {
            return Err(StoreError::NotDispatchable { id: record.attempt });
        }
        let mut attempt =
            load_attempt(&transaction, &record.attempt)?.ok_or_else(|| StoreError::Missing {
                kind: "attempt",
                id: record.attempt.to_string(),
            })?;
        record.receipt = receipt;
        record.ended_at = Some(Timestamp::now().to_string());
        record.state = if completed {
            ReconciliationState::Completed
        } else if record.receipt.is_some() {
            ReconciliationState::Unknown
        } else {
            ReconciliationState::Failed
        };
        transaction
            .execute(
                "UPDATE reconciliations SET state = ?2, json = ?3 WHERE request_id = ?1",
                params![
                    request.as_str(),
                    reconciliation_state_text(record.state),
                    encode(&record)?
                ],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
        if completed {
            attempt.state = AttemptState::Completed;
            attempt.updated_at = Timestamp::now().to_string();
            update_attempt(&transaction, &attempt)?;
            if release_lease {
                release_leases(&transaction, &attempt)?;
            }
        } else if attempt.state == AttemptState::Partial {
            attempt.state = AttemptState::Unknown;
            attempt.updated_at = Timestamp::now().to_string();
            update_attempt(&transaction, &attempt)?;
        }
        transaction
            .commit()
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(attempt)
    }

    pub fn reconciliation_history(
        &self,
        attempt: &AttemptId,
    ) -> Result<Vec<ReconciliationRecord>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT json FROM reconciliations WHERE attempt_id = ?1 ORDER BY ordinal ASC")
            .map_err(|source| StoreError::Sqlite { source })?;
        statement
            .query_map([attempt.as_str()], |row| row.get::<_, String>(0))
            .map_err(|source| StoreError::Sqlite { source })?
            .map(|row| {
                row.map_err(|source| StoreError::Sqlite { source })
                    .and_then(|json| decode(&json))
            })
            .collect()
    }

    pub fn integrity_check(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let result: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|source| StoreError::Sqlite { source })?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Integrity { message: result })
        }
    }

    pub fn backup_to(&self, path: impl AsRef<Path>) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let mut destination = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|source| StoreError::Sqlite { source })?;
        let backup = rusqlite::backup::Backup::new(&connection, &mut destination)
            .map_err(|source| StoreError::Sqlite { source })?;
        backup
            .run_to_completion(5, std::time::Duration::from_millis(5), None)
            .map_err(|source| StoreError::Sqlite { source })
    }

    fn from_connection(
        connection: Connection,
        journal_lock: Option<File>,
    ) -> Result<Self, StoreError> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|source| StoreError::Sqlite { source })?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|source| StoreError::Sqlite { source })?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, digest TEXT NOT NULL, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL, plan_id TEXT NOT NULL, operation_index INTEGER NOT NULL, state TEXT NOT NULL, json TEXT NOT NULL);
             CREATE UNIQUE INDEX IF NOT EXISTS attempts_grant_plan_operation_unique ON attempts(grant_id, plan_id, operation_index);
             CREATE TABLE IF NOT EXISTS reconciliations (request_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, ordinal INTEGER NOT NULL, state TEXT NOT NULL, json TEXT NOT NULL, UNIQUE(attempt_id, ordinal));
             CREATE UNIQUE INDEX IF NOT EXISTS reconciliations_active_attempt ON reconciliations(attempt_id) WHERE state = 'claimed';
             CREATE TABLE IF NOT EXISTS recovery_takeovers (request_id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS recovery_source_retirements (grant_id TEXT NOT NULL, plan_id TEXT NOT NULL, takeover_request TEXT NOT NULL, PRIMARY KEY(grant_id, plan_id));
             CREATE TABLE IF NOT EXISTS halted_run_abandonments (request_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL, plan_id TEXT NOT NULL, json TEXT NOT NULL, UNIQUE(grant_id, plan_id));
             CREATE TABLE IF NOT EXISTS plan_leases (resource_key TEXT PRIMARY KEY, grant_id TEXT NOT NULL, plan_id TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS case_facts (case_id TEXT NOT NULL, ordinal INTEGER NOT NULL, json TEXT NOT NULL, PRIMARY KEY(case_id, ordinal));"
        ).map_err(|source| StoreError::Sqlite { source })?;
        recover_interrupted_dispatches(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            _journal_lock: journal_lock,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }

    fn save_entity<T: Serialize>(
        &self,
        table: &str,
        id: &str,
        entity: &T,
    ) -> Result<(), StoreError> {
        let query = format!(
            "INSERT INTO {table} (id, json) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET json = excluded.json"
        );
        let connection = self.lock()?;
        connection
            .execute(&query, params![id, encode(entity)?])
            .map_err(|source| StoreError::Sqlite { source })?;
        Ok(())
    }

    fn save_immutable<T: Serialize + DeserializeOwned>(
        &self,
        table: &str,
        id: &str,
        entity: &T,
    ) -> Result<(), StoreError> {
        let encoded = encode(entity)?;
        let query =
            format!("INSERT INTO {table} (id, json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING");
        let connection = self.lock()?;
        let inserted = connection
            .execute(&query, params![id, encoded])
            .map_err(|source| StoreError::Sqlite { source })?;
        if inserted == 1 {
            return Ok(());
        }
        let existing: T =
            load_entity_from(&connection, table, id)?.ok_or_else(|| StoreError::Missing {
                kind: "immutable record",
                id: id.to_owned(),
            })?;
        if encode(&existing)? == encode(entity)? {
            Ok(())
        } else {
            Err(StoreError::Conflict {
                kind: "immutable record",
                id: id.to_owned(),
            })
        }
    }

    fn load_entity<T: DeserializeOwned>(
        &self,
        table: &str,
        id: &str,
    ) -> Result<Option<T>, StoreError> {
        let query = format!("SELECT json FROM {table} WHERE id = ?1");
        let connection = self.lock()?;
        let value = connection
            .query_row(&query, [id], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|source| StoreError::Sqlite { source })?;
        value.map(|json| decode(&json)).transpose()
    }
}

fn recover_interrupted_dispatches(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = connection
        .prepare("SELECT json FROM attempts WHERE state = 'dispatched'")
        .map_err(|source| StoreError::Sqlite { source })?;
    let records = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| StoreError::Sqlite { source })?
        .map(|row| {
            row.map_err(|source| StoreError::Sqlite { source })
                .and_then(|json| decode(&json))
        })
        .collect::<Result<Vec<AttemptRecord>, StoreError>>()?;
    for mut attempt in records {
        attempt.state = AttemptState::Unknown;
        attempt.receipt = Some(OperationReceipt::Unknown {
            reason: "process interrupted after dispatch; reconciliation required".to_owned(),
            observation: None,
        });
        attempt.updated_at = Timestamp::now().to_string();
        update_attempt(connection, &attempt)?;
    }
    let mut statement = connection
        .prepare("SELECT json FROM reconciliations WHERE state = 'claimed'")
        .map_err(|source| StoreError::Sqlite { source })?;
    let records = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| StoreError::Sqlite { source })?
        .map(|row| {
            row.map_err(|source| StoreError::Sqlite { source })
                .and_then(|json| decode::<ReconciliationRecord>(&json))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    for mut record in records {
        record.state = ReconciliationState::Unknown;
        record.ended_at = Some(Timestamp::now().to_string());
        connection
            .execute(
                "UPDATE reconciliations SET state = ?2, json = ?3 WHERE request_id = ?1",
                params![
                    record.request.as_str(),
                    reconciliation_state_text(record.state),
                    encode(&record)?
                ],
            )
            .map_err(|source| StoreError::Sqlite { source })?;
    }
    Ok(())
}

fn acquire_journal_lock(database: &Path) -> Result<File, StoreError> {
    let path = database.with_extension("lock");
    if path.exists()
        && fs::symlink_metadata(&path)
            .map_err(|source| StoreError::Io { source })?
            .file_type()
            .is_symlink()
    {
        return Err(StoreError::AlreadyOpen { path });
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| StoreError::Io { source })?;
    file.try_lock()
        .map_err(|_| StoreError::AlreadyOpen { path })?;
    Ok(file)
}

fn encode<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|source| StoreError::Json { source })
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, StoreError> {
    serde_json::from_str(value).map_err(|source| StoreError::Json { source })
}

fn sqlite_unsigned(field: &'static str, value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange { field, value })
}

fn sqlite_index(field: &'static str, value: usize) -> Result<i64, StoreError> {
    let value = u64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: u64::MAX,
    })?;
    sqlite_unsigned(field, value)
}

fn stored_unsigned(field: &'static str, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::NegativeStoredInteger { field, value })
}

fn stored_index(field: &'static str, value: i64) -> Result<usize, StoreError> {
    let value = stored_unsigned(field, value)?;
    usize::try_from(value).map_err(|_| StoreError::IntegerOutOfRange { field, value })
}

fn load_entity_from<T: DeserializeOwned>(
    connection: &Connection,
    table: &str,
    id: &str,
) -> Result<Option<T>, StoreError> {
    let query = format!("SELECT json FROM {table} WHERE id = ?1");
    let value = connection
        .query_row(&query, [id], |row| row.get::<_, String>(0))
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn load_attempt_by_request(
    connection: &Connection,
    request: &RequestId,
) -> Result<Option<AttemptRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM attempts WHERE request_id = ?1",
            [request.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn load_attempt(
    connection: &Connection,
    id: &AttemptId,
) -> Result<Option<AttemptRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM attempts WHERE id = ?1",
            [id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn load_reconciliation_by_request(
    connection: &Connection,
    request: &RequestId,
) -> Result<Option<ReconciliationRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM reconciliations WHERE request_id = ?1",
            [request.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn load_recovery_takeover(
    connection: &Connection,
    request: &RequestId,
) -> Result<Option<RecoveryTakeoverRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM recovery_takeovers WHERE request_id = ?1",
            [request.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn recovery_destination_exists(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<bool, StoreError> {
    let mut statement = connection
        .prepare("SELECT json FROM recovery_takeovers")
        .map_err(|source| StoreError::Sqlite { source })?;
    let records = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| StoreError::Sqlite { source })?
        .map(|row| {
            row.map_err(|source| StoreError::Sqlite { source })
                .and_then(|json| decode::<RecoveryTakeoverRecord>(&json))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    Ok(records
        .iter()
        .any(|record| record.grant == *grant && record.plan == *plan))
}

fn recovery_source_retired(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM recovery_source_retirements WHERE grant_id = ?1 AND plan_id = ?2",
            params![grant.as_str(), plan.as_str()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })
        .map(|value| value.is_some())
}

fn source_pair_has_dispatched(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM attempts WHERE grant_id = ?1 AND plan_id = ?2 AND state = 'dispatched'",
            params![grant.as_str(), plan.as_str()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })
        .map(|value| value.is_some())
}

fn source_pair_has_active_reconciliation(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM reconciliations AS r JOIN attempts AS a ON a.id = r.attempt_id WHERE a.grant_id = ?1 AND a.plan_id = ?2 AND r.state = 'claimed'",
            params![grant.as_str(), plan.as_str()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })
        .map(|value| value.is_some())
}

fn load_halted_run_abandonment_by_request(
    connection: &Connection,
    request: &RequestId,
) -> Result<Option<HaltedRunAbandonmentRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM halted_run_abandonments WHERE request_id = ?1",
            [request.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn load_halted_run_abandonment_by_run(
    connection: &Connection,
    run: &RequestId,
) -> Result<Option<HaltedRunAbandonmentRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM halted_run_abandonments WHERE run_id = ?1",
            [run.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn halted_pair_exists(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT 1 FROM halted_run_abandonments WHERE grant_id = ?1 AND plan_id = ?2",
            params![grant.as_str(), plan.as_str()],
            |_| Ok(()),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })
        .map(|value| value.is_some())
}

fn lease_keys_for_pair(
    connection: &Connection,
    grant: &GrantId,
    plan: &PlanId,
) -> Result<std::collections::BTreeSet<String>, StoreError> {
    connection
        .prepare("SELECT resource_key FROM plan_leases WHERE grant_id = ?1 AND plan_id = ?2")
        .map_err(|source| StoreError::Sqlite { source })?
        .query_map(params![grant.as_str(), plan.as_str()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|source| StoreError::Sqlite { source })?
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|source| StoreError::Sqlite { source })
}

fn load_active_reconciliation(
    connection: &Connection,
    attempt: &AttemptId,
) -> Result<Option<ReconciliationRecord>, StoreError> {
    let value = connection
        .query_row(
            "SELECT json FROM reconciliations WHERE attempt_id = ?1 AND state = 'claimed'",
            [attempt.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| StoreError::Sqlite { source })?;
    value.map(|json| decode(&json)).transpose()
}

fn update_attempt(connection: &Connection, attempt: &AttemptRecord) -> Result<(), StoreError> {
    connection
        .execute(
            "UPDATE attempts SET state = ?2, json = ?3 WHERE id = ?1",
            params![
                attempt.id.as_str(),
                state_text(attempt.state),
                encode(attempt)?
            ],
        )
        .map_err(|source| StoreError::Sqlite { source })?;
    Ok(())
}

fn release_leases(connection: &Connection, attempt: &AttemptRecord) -> Result<(), StoreError> {
    for resource in &attempt.leased_resources {
        connection.execute("DELETE FROM plan_leases WHERE resource_key = ?1 AND grant_id = ?2 AND plan_id = ?3", params![resource.key(), attempt.grant.as_str(), attempt.plan.as_str()]).map_err(|source| StoreError::Sqlite { source })?;
    }
    Ok(())
}

fn state_text(state: AttemptState) -> &'static str {
    match state {
        AttemptState::Intent => "intent",
        AttemptState::Dispatched => "dispatched",
        AttemptState::Completed => "completed",
        AttemptState::Partial => "partial",
        AttemptState::Unknown => "unknown",
        AttemptState::Rejected => "rejected",
    }
}

fn reconciliation_state_text(state: ReconciliationState) -> &'static str {
    match state {
        ReconciliationState::Claimed => "claimed",
        ReconciliationState::Completed => "completed",
        ReconciliationState::Unknown => "unknown",
        ReconciliationState::Failed => "failed",
    }
}

fn same_recovery_takeover(left: &RecoveryTakeoverRecord, right: &RecoveryTakeoverRecord) -> bool {
    left.request == right.request
        && left.run == right.run
        && left.first_attempt == right.first_attempt
        && left.unresolved == right.unresolved
        && left.grant == right.grant
        && left.plan == right.plan
        && left.resources == right.resources
        && left.justification_evidence == right.justification_evidence
        && left.authorized_by == right.authorized_by
}

fn same_halted_run_abandonment(
    left: &HaltedRunAbandonmentRecord,
    right: &HaltedRunAbandonmentRecord,
) -> bool {
    left.request == right.request
        && left.run == right.run
        && left.grant == right.grant
        && left.plan == right.plan
        && left.resources == right.resources
        && left.justification_evidence == right.justification_evidence
        && left.authorized_by == right.authorized_by
}

#[cfg(test)]
mod tests {
    use super::{StoreError, sqlite_unsigned, stored_unsigned};

    #[test]
    fn sqlite_unsigned_preserves_the_signed_sqlite_boundary() {
        assert!(matches!(
            sqlite_unsigned("ordinal", i64::MAX as u64),
            Ok(value) if value == i64::MAX
        ));
        assert!(matches!(
            sqlite_unsigned("ordinal", i64::MAX as u64 + 1),
            Err(StoreError::IntegerOutOfRange { .. })
        ));
    }

    #[test]
    fn stored_unsigned_rejects_negative_database_values() {
        assert!(matches!(
            stored_unsigned("ordinal", -1),
            Err(StoreError::NegativeStoredInteger { .. })
        ));
    }
}
