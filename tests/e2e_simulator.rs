//! End-to-end simulator coverage through the authenticated Unix service.
//!
//! This is deliberately an integration test rather than a hardware tutorial:
//! every request crosses the local daemon boundary, and the simulator persists
//! only under a disposable instance root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use cheirismos::domain::{
    ArtifactDigest, AttemptId, AttemptRecord, Budget, Capability, CaseFact, CaseId,
    CommissionedProfile, EffectPermission, ElectricalLimits, FixtureSessionId, Grant, GrantId,
    InstrumentBinding, InstrumentId, Operation, PlanId, PlanProposal, PlannedOperation, Principal,
    PrincipalId, ProfileId, ReconciliationSetup, RegionLimits, RequestId, SimulatorId, TargetId,
};
use cheirismos::evidence::ArtifactStore;
use cheirismos::instruments::{InstrumentConfig, SimulatorConfig};
use cheirismos::service::api::{
    AuthorityRequest, CaseRequest, EvidenceRequest, ExperimentRequest, InstrumentRequest,
    ServiceApi, ServiceRequest, SystemRequest,
};
use cheirismos::service::backend::{DeviceBackend, DeviceBinding};
use cheirismos::service::client::{self, ClientError};
use cheirismos::service::config::ServiceConfig;
use cheirismos::service::server::UnixServiceServer;
use cheirismos::store::SqliteStore;
use cheirismos::supervisor::Supervisor;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

fn digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::sha256(bytes)
}

fn id<T>(value: &str) -> Result<T, cheirismos::domain::DomainError>
where
    T: TryFrom<String, Error = cheirismos::domain::DomainError>,
{
    value.to_owned().try_into()
}

fn credential(config: &ServiceConfig, role: &str) -> PathBuf {
    config
        .instance_dir
        .join("credentials")
        .join(format!("{role}.token"))
}

fn simulator_binding(
    identity: &str,
    target: &[u8],
    fixture: &[u8],
) -> Result<DeviceBinding, cheirismos::domain::DomainError> {
    Ok(DeviceBinding {
        config: InstrumentConfig::Simulator(SimulatorConfig {
            identity: id::<SimulatorId>(identity)?,
            flash_bytes: 1024,
        }),
        target_fingerprint: digest(target),
        fixture_revision: digest(fixture),
        flash_identity: None,
    })
}

fn configure_simulators(config: &mut ServiceConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.instruments = BTreeMap::from([
        (
            id::<InstrumentId>("sim-flash")?,
            simulator_binding(
                "disposable-flash-target",
                b"flash-target",
                b"fixture-revision",
            )?,
        ),
        (
            id::<InstrumentId>("sim-relay")?,
            simulator_binding(
                "disposable-relay-target",
                b"relay-target",
                b"fixture-revision",
            )?,
        ),
    ]);
    fs::remove_file(config.instance_dir.join("service.json"))?;
    config.save()?;
    Ok(())
}

async fn start_daemon(config: ServiceConfig) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    let artifacts = Arc::new(ArtifactStore::open(config.instance_dir.join("artifacts"))?);
    let store = Arc::new(SqliteStore::open(config.instance_dir.join("state.sqlite"))?);
    let backend = Arc::new(DeviceBackend::open(
        config.instruments.clone(),
        config.instance_dir.join("runtime"),
        Arc::clone(&artifacts),
        tokio::runtime::Handle::current(),
    )?);
    let principals = config
        .credentials
        .iter()
        .map(|binding| {
            (
                binding.principal.clone(),
                Principal {
                    id: binding.principal.clone(),
                    role: binding.role,
                    authentication_fingerprint: binding.token_digest.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let api = Arc::new(ServiceApi::new(
        Arc::new(Supervisor::new(store, Arc::clone(&artifacts))),
        artifacts,
        backend.clone(),
        Some(backend),
        principals,
    ));
    let server = UnixServiceServer::new(config.clone(), api);
    let task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..50 {
        if config.socket.exists() {
            return Ok(task);
        }
        sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    Err("simulator daemon did not bind its Unix socket".into())
}

async fn stop_daemon(task: JoinHandle<()>, socket: &Path) {
    task.abort();
    let _ = task.await;
    let _ = fs::remove_file(socket);
}

async fn request(
    config: &ServiceConfig,
    role: &str,
    value: ServiceRequest,
) -> Result<cheirismos::service::api::ServiceResponse, ClientError> {
    client::request(&config.socket, credential(config, role), value).await
}

async fn import(
    config: &ServiceConfig,
    case: &CaseId,
    bytes: &[u8],
) -> Result<ArtifactDigest, Box<dyn std::error::Error>> {
    let response = request(
        config,
        "agent",
        ServiceRequest::Evidence(EvidenceRequest::Import {
            case: case.clone(),
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }),
    )
    .await?;
    Ok(serde_json::from_value(response.result["artifact"].clone())?)
}

async fn inspect(
    config: &ServiceConfig,
    instrument: InstrumentId,
) -> Result<cheirismos::domain::Observation, Box<dyn std::error::Error>> {
    let response = request(
        config,
        "operator",
        ServiceRequest::Instrument(InstrumentRequest::Inspect { instrument }),
    )
    .await?;
    Ok(serde_json::from_value(response.result)?)
}

struct ProfileFixture<'a> {
    name: &'a str,
    target: &'a str,
    instrument: InstrumentId,
    binding: &'a DeviceBinding,
    observation: &'a cheirismos::domain::Observation,
    capabilities: BTreeSet<Capability>,
    permissions: BTreeSet<EffectPermission>,
}

struct PlanArtifacts {
    candidate: ArtifactDigest,
    tool: ArtifactDigest,
    precondition: ArtifactDigest,
}

fn profile(input: ProfileFixture<'_>) -> Result<CommissionedProfile, Box<dyn std::error::Error>> {
    let configuration_digest = serde_json::from_value(
        input
            .observation
            .body
            .get("configuration_digest")
            .cloned()
            .ok_or("inspection did not contain configuration digest")?,
    )?;
    let physical_identity = serde_json::from_value(
        input
            .observation
            .body
            .get("physical_identity")
            .cloned()
            .ok_or("inspection did not contain physical identity")?,
    )?;
    let qualification_evidence = input
        .observation
        .evidence
        .clone()
        .ok_or("inspection did not create commissioning evidence")?;
    Ok(CommissionedProfile {
        id: id::<ProfileId>(&format!("profile-{}", input.name))?,
        target: id::<TargetId>(input.target)?,
        target_fingerprint: input.binding.target_fingerprint.clone(),
        instruments: BTreeMap::from([(
            input.instrument,
            InstrumentBinding {
                fingerprint: input.observation.source_fingerprint.clone(),
                physical_identity,
                configuration_digest,
                qualified_capabilities: input.capabilities.clone(),
                qualified_effect_permissions: input.permissions.clone(),
                qualification_evidence: qualification_evidence.clone(),
            },
        )]),
        fixture_revision: input.binding.fixture_revision.clone(),
        fixture_session: id::<FixtureSessionId>("simulator-fixture-session")?,
        permitted_capabilities: input.capabilities,
        electrical_limits: ElectricalLimits {
            max_millivolts: 0,
            max_milliamps: 0,
        },
        region_limits: RegionLimits {
            flash_start: 0,
            flash_end_exclusive: 1024,
        },
        commissioning_evidence: qualification_evidence,
        live_interlocks: Vec::new(),
    })
}

fn grant(
    name: &str,
    profile: &CommissionedProfile,
    capabilities: BTreeSet<Capability>,
    permissions: BTreeSet<EffectPermission>,
) -> Result<Grant, Box<dyn std::error::Error>> {
    Ok(Grant {
        id: id::<GrantId>(&format!("grant-{name}"))?,
        issued_by: id::<PrincipalId>("operator")?,
        agent: id::<PrincipalId>("agent")?,
        target: profile.target.clone(),
        profile: profile.id.clone(),
        capabilities,
        effect_permissions: permissions,
        remaining: Budget::try_new(12, 128, 5_000)?,
        expires_at: "2099-01-01T00:00:00Z".to_owned(),
        revoked: false,
    })
}

async fn review_and_execute(
    config: &ServiceConfig,
    name: &str,
    profile: &CommissionedProfile,
    grant: &Grant,
    artifacts: &PlanArtifacts,
    operation: Operation,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let proposal = PlanProposal {
        id: id::<PlanId>(&format!("plan-{name}"))?,
        candidate_digest: artifacts.candidate.clone(),
        fixture_revision: profile.fixture_revision.clone(),
        tool_digest: artifacts.tool.clone(),
        target_fingerprint: profile.target_fingerprint.clone(),
        instrument_fingerprints: profile
            .instruments
            .iter()
            .map(|(instrument, binding)| (instrument.clone(), binding.fingerprint.clone()))
            .collect(),
        instrument_configuration_digests: profile
            .instruments
            .iter()
            .map(|(instrument, binding)| (instrument.clone(), binding.configuration_digest.clone()))
            .collect(),
        preconditions: vec![artifacts.precondition.clone()],
        operations: vec![PlannedOperation {
            operation,
            max_milliseconds: 500,
            postconditions: Vec::new(),
        }],
        requested_by: id::<PrincipalId>("agent")?,
        reconciliation_setup: ReconciliationSetup::ObservationOnly,
    };
    let response = request(
        config,
        "agent",
        ServiceRequest::Experiment(ExperimentRequest::Propose { proposal }),
    )
    .await?;
    let proposal: PlanProposal = serde_json::from_value(response.result)?;
    request(
        config,
        "reviewer",
        ServiceRequest::Experiment(ExperimentRequest::Review {
            plan: proposal.id.clone(),
            expected_digest: proposal.digest()?,
        }),
    )
    .await?;
    let attempt = id::<AttemptId>(&format!("attempt-{name}"))?;
    request(
        config,
        "agent",
        ServiceRequest::Experiment(ExperimentRequest::Execute {
            grant: grant.id.clone(),
            plan: proposal.id,
            run: id::<RequestId>(&format!("run-{name}"))?,
            first_attempt: attempt.clone(),
        }),
    )
    .await?;
    for _ in 0..100 {
        let response = request(
            config,
            "agent",
            ServiceRequest::Experiment(ExperimentRequest::Attempt {
                attempt: attempt.clone(),
            }),
        )
        .await?;
        let record: AttemptRecord = serde_json::from_value(response.result)?;
        if record.state.is_terminal() {
            return Ok(record);
        }
        sleep(Duration::from_millis(10)).await;
    }
    Err(format!("simulator attempt {name} did not finish").into())
}

fn completed_observation(
    attempt: AttemptRecord,
) -> Result<cheirismos::domain::Observation, Box<dyn std::error::Error>> {
    match attempt.receipt.ok_or("attempt did not have a receipt")? {
        cheirismos::domain::OperationReceipt::Completed { observation } => Ok(observation),
        receipt => Err(format!("simulator operation did not complete: {receipt:?}").into()),
    }
}

fn copy_tree(from: &Path, into: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(into)?;
    fs::set_permissions(into, fs::metadata(from)?.permissions())?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let source = entry.path();
        let destination = into.join(entry.file_name());
        if source.is_dir() {
            copy_tree(&source, &destination)?;
        } else if source.is_file() {
            fs::copy(&source, &destination)?;
            fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn simulator_daemon_commissions_reviews_executes_and_restores()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let mut config = ServiceConfig::initialize(root.path().join("instance"))?;
    configure_simulators(&mut config)?;
    let daemon = start_daemon(config.clone()).await?;

    let inventory = request(
        &config,
        "operator",
        ServiceRequest::System(SystemRequest::Status {}),
    )
    .await?;
    assert_eq!(
        inventory
            .result
            .as_array()
            .ok_or("inventory was not an array")?
            .len(),
        2
    );

    let case = id::<CaseId>("simulator-case")?;
    let candidate = import(&config, &case, &[0x0f, 0xf0, 0xaa, 0x55]).await?;
    let tool = import(&config, &case, b"simulator-tool-v1").await?;
    let precondition = import(&config, &case, b"isolated simulator fixture is powered off").await?;
    let artifacts = PlanArtifacts {
        candidate: candidate.clone(),
        tool: tool.clone(),
        precondition: precondition.clone(),
    };
    request(
        &config,
        "agent",
        ServiceRequest::Case(CaseRequest::Append {
            case: case.clone(),
            fact: CaseFact::Claim {
                statement: "simulator evidence is scoped to disposable targets".to_owned(),
                evidence: vec![candidate.clone(), precondition.clone()],
            },
        }),
    )
    .await?;

    let flash_id = id::<InstrumentId>("sim-flash")?;
    let relay_id = id::<InstrumentId>("sim-relay")?;
    let flash_observation = inspect(&config, flash_id.clone()).await?;
    let relay_observation = inspect(&config, relay_id.clone()).await?;
    let flash_binding = config
        .instruments
        .get(&flash_id)
        .ok_or("flash binding missing")?;
    let relay_binding = config
        .instruments
        .get(&relay_id)
        .ok_or("relay binding missing")?;
    let flash_permissions = BTreeSet::from([
        EffectPermission::InstrumentConfigure,
        EffectPermission::FlashWrite,
    ]);
    let relay_permissions = BTreeSet::from([EffectPermission::RelayActuate]);
    let flash_profile = profile(ProfileFixture {
        name: "flash",
        target: "target-flash",
        instrument: flash_id.clone(),
        binding: flash_binding,
        observation: &flash_observation,
        capabilities: BTreeSet::from([Capability::Flash]),
        permissions: flash_permissions.clone(),
    })?;
    let relay_profile = profile(ProfileFixture {
        name: "relay",
        target: "target-relay",
        instrument: relay_id.clone(),
        binding: relay_binding,
        observation: &relay_observation,
        capabilities: BTreeSet::from([Capability::Relay]),
        permissions: relay_permissions.clone(),
    })?;

    assert!(matches!(
        request(
            &config,
            "agent",
            ServiceRequest::Authority(AuthorityRequest::Commission {
                profile: flash_profile.clone(),
            }),
        )
        .await,
        Err(ClientError::Refused { .. })
    ));
    for (profile, grant) in [
        (
            &flash_profile,
            grant(
                "flash",
                &flash_profile,
                BTreeSet::from([Capability::Flash]),
                flash_permissions,
            )?,
        ),
        (
            &relay_profile,
            grant(
                "relay",
                &relay_profile,
                BTreeSet::from([Capability::Relay]),
                relay_permissions,
            )?,
        ),
    ] {
        request(
            &config,
            "operator",
            ServiceRequest::Authority(AuthorityRequest::Commission {
                profile: profile.clone(),
            }),
        )
        .await?;
        request(
            &config,
            "operator",
            ServiceRequest::Authority(AuthorityRequest::IssueGrant {
                agent: id::<PrincipalId>("agent")?,
                grant,
            }),
        )
        .await?;
    }
    let flash_grant = grant(
        "flash",
        &flash_profile,
        BTreeSet::from([Capability::Flash]),
        BTreeSet::from([
            EffectPermission::InstrumentConfigure,
            EffectPermission::FlashWrite,
        ]),
    )?;
    let relay_grant = grant(
        "relay",
        &relay_profile,
        BTreeSet::from([Capability::Relay]),
        BTreeSet::from([EffectPermission::RelayActuate]),
    )?;

    completed_observation(
        review_and_execute(
            &config,
            "flash-write",
            &flash_profile,
            &flash_grant,
            &artifacts,
            Operation::FlashWrite {
                target: flash_profile.target.clone(),
                instrument: flash_id.clone(),
                offset: 16,
                source: candidate.clone(),
                length: 4,
            },
        )
        .await?,
    )?;
    let verify = completed_observation(
        review_and_execute(
            &config,
            "flash-verify",
            &flash_profile,
            &flash_grant,
            &artifacts,
            Operation::FlashVerify {
                target: flash_profile.target.clone(),
                instrument: flash_id.clone(),
                offset: 16,
                source: candidate.clone(),
                length: 4,
            },
        )
        .await?,
    )?;
    assert_eq!(verify.body["matches_candidate"], true);
    let read = completed_observation(
        review_and_execute(
            &config,
            "flash-read",
            &flash_profile,
            &flash_grant,
            &artifacts,
            Operation::FlashRead {
                target: flash_profile.target.clone(),
                instrument: flash_id.clone(),
                offset: 16,
                length: 4,
            },
        )
        .await?,
    )?;
    let read_artifact: ArtifactDigest = serde_json::from_value(read.body["artifact"].clone())?;
    let bytes = request(
        &config,
        "agent",
        ServiceRequest::Evidence(EvidenceRequest::Fetch {
            artifact: read_artifact,
            offset: 0,
            max_bytes: 4,
        }),
    )
    .await?;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(
            bytes.result["bytes_base64"]
                .as_str()
                .ok_or("read response did not contain bytes")?,
        )?,
        vec![0x0f, 0xf0, 0xaa, 0x55]
    );

    for (name, closed) in [
        ("relay-close", true),
        ("relay-read", true),
        ("relay-open", false),
    ] {
        let operation = if name == "relay-read" {
            Operation::RelayRead {
                target: relay_profile.target.clone(),
                instrument: relay_id.clone(),
                relay: 0,
            }
        } else {
            Operation::RelaySet {
                target: relay_profile.target.clone(),
                instrument: relay_id.clone(),
                relay: 0,
                closed,
            }
        };
        let observation = completed_observation(
            review_and_execute(
                &config,
                name,
                &relay_profile,
                &relay_grant,
                &artifacts,
                operation,
            )
            .await?,
        )?;
        assert_eq!(observation.body["closed"], closed);
    }

    stop_daemon(daemon, &config.socket).await;
    let offline_backup = root.path().join("offline-backup");
    copy_tree(&config.instance_dir, &offline_backup)?;
    let pre_restore = root.path().join("pre-restore");
    fs::rename(&config.instance_dir, &pre_restore)?;
    fs::rename(&offline_backup, &config.instance_dir)?;
    let restored = ServiceConfig::load(config.instance_dir.join("service.json"))?;
    let restarted = start_daemon(restored.clone()).await?;
    let persisted = request(
        &restored,
        "agent",
        ServiceRequest::Experiment(ExperimentRequest::Attempt {
            attempt: id::<AttemptId>("attempt-flash-read")?,
        }),
    )
    .await?;
    let persisted: AttemptRecord = serde_json::from_value(persisted.result)?;
    assert!(persisted.state.is_terminal());
    let restored_relay = inspect(&restored, relay_id).await?;
    assert_eq!(restored_relay.body["status"]["relay_closed"][0], false);
    stop_daemon(restarted, &restored.socket).await;
    Ok(())
}
