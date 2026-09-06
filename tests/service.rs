//! Local-service transport tests that never open hardware.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use cheirismos::domain::{CaseId, InstrumentId, OperationReceipt, Principal};
use cheirismos::evidence::ArtifactStore;
use cheirismos::service::api::{
    EvidenceRequest, InstrumentRequest, ServiceApi, ServiceRequest, SystemRequest,
};
use cheirismos::service::client::{self, ClientError};
use cheirismos::service::config::ServiceConfig;
use cheirismos::service::mcp::McpService;
use cheirismos::service::server::UnixServiceServer;
use cheirismos::store::SqliteStore;
use cheirismos::supervisor::{
    ArtifactResolver, Backend, BackendError, DispatchRequest, ReconciliationRequest, Supervisor,
};
use tempfile::TempDir;
use tokio::time::{Duration, sleep};

#[derive(Debug, Clone, Default)]
struct McpTestClient;

impl rmcp::ClientHandler for McpTestClient {
    fn get_info(&self) -> rmcp::model::ClientInfo {
        rmcp::model::ClientInfo::default()
    }
}

/// Backend double proves transport tests do not contact a physical instrument.
struct TestBackend;

impl Backend for TestBackend {
    fn execute(
        &self,
        _request: &DispatchRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError> {
        Err(BackendError::Transport {
            message: "test backend does not execute effects".to_owned(),
        })
    }

    fn reconcile(
        &self,
        _request: &ReconciliationRequest,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<OperationReceipt, BackendError> {
        Err(BackendError::Transport {
            message: "test backend does not reconcile effects".to_owned(),
        })
    }

    fn preflight(
        &self,
        _operation: &cheirismos::domain::Operation,
        _profile: &cheirismos::domain::CommissionedProfile,
        _artifacts: &dyn ArtifactResolver,
    ) -> Result<(), BackendError> {
        Ok(())
    }
}

async fn start_service()
-> Result<(TempDir, ServiceConfig, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = ServiceConfig::initialize(directory.path().join("instance"))?;
    let artifacts = Arc::new(ArtifactStore::open(config.instance_dir.join("artifacts"))?);
    let store = Arc::new(SqliteStore::open(config.instance_dir.join("state.sqlite"))?);
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
    let backend: Arc<dyn Backend> = Arc::new(TestBackend);
    let api = Arc::new(ServiceApi::new(
        Arc::new(Supervisor::new(store, Arc::clone(&artifacts))),
        Arc::clone(&artifacts),
        backend,
        None,
        principals,
    ));
    let server = UnixServiceServer::new(config.clone(), api);
    let task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..20 {
        if config.socket.exists() {
            return Ok((directory, config, task));
        }
        sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    Err("local service did not bind its Unix socket".into())
}

fn credential(config: &ServiceConfig, role: &str) -> std::path::PathBuf {
    config
        .instance_dir
        .join("credentials")
        .join(format!("{role}.token"))
}

#[test]
fn service_request_rejects_unknown_fields() {
    let request = serde_json::json!({
        "family": "system",
        "request": { "action": "status", "unexpected": true }
    });
    assert!(serde_json::from_value::<ServiceRequest>(request).is_err());
}

#[tokio::test]
async fn agent_cannot_inspect_an_instrument() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, task) = start_service().await?;
    let request = ServiceRequest::Instrument(InstrumentRequest::Inspect {
        instrument: InstrumentId::try_from("simulator-a")?,
    });
    let result = client::request(&config.socket, credential(&config, "agent"), request).await;
    task.abort();
    assert!(matches!(result, Err(ClientError::Refused { .. })));
    Ok(())
}

#[tokio::test]
async fn client_imports_case_artifact_through_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, task) = start_service().await?;
    let response = client::request(
        &config.socket,
        credential(&config, "agent"),
        ServiceRequest::Evidence(EvidenceRequest::Import {
            case: CaseId::try_from("case-a")?,
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(b"artifact bytes"),
        }),
    )
    .await?;
    task.abort();
    assert!(matches!(
        response.status,
        cheirismos::service::api::ResponseStatus::Reported
    ));
    assert!(response.result.get("artifact").is_some());
    Ok(())
}

#[tokio::test]
async fn client_reads_daemon_status() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, config, task) = start_service().await?;
    let response = client::request(
        &config.socket,
        credential(&config, "operator"),
        ServiceRequest::System(SystemRequest::Status {}),
    )
    .await?;
    task.abort();
    assert!(matches!(
        response.status,
        cheirismos::service::api::ResponseStatus::Reported
    ));
    Ok(())
}

#[tokio::test]
async fn mcp_sdk_lists_and_proxies_system_tool_to_daemon() -> Result<(), Box<dyn std::error::Error>>
{
    use rmcp::{ServiceExt as _, model::CallToolRequestParams};

    let (_directory, config, daemon) = start_service().await?;
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
    let mcp = McpService::new(config.socket.clone(), credential(&config, "operator"));
    let mcp_task = tokio::spawn(async move {
        if let Ok(service) = mcp.serve(server_transport).await {
            let _ = service.waiting().await;
        }
    });
    let client = McpTestClient.serve(client_transport).await?;
    let tools = client.peer().list_tools(None).await?;
    assert!(
        tools
            .tools
            .iter()
            .any(|tool| tool.name == "cheirismos_system")
    );
    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "request".to_owned(),
        serde_json::json!({ "action": "status" }),
    );
    let result = client
        .peer()
        .call_tool(CallToolRequestParams::new("cheirismos_system").with_arguments(arguments))
        .await?;
    daemon.abort();
    mcp_task.abort();
    assert!(!result.content.is_empty());
    Ok(())
}
