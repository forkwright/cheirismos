//! Cheirismos local CLI, authenticated Unix service, and MCP stdio entrypoint.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use clap::{Parser, Subcommand};
use koinon::cli::GlobalArgs;
use snafu::Snafu;

use cheirismos::evidence::ArtifactStore;
use cheirismos::service::api::{EvidenceRequest, ServiceApi, ServiceRequest, SystemRequest};
use cheirismos::service::backend::DeviceBackend;
use cheirismos::service::client;
use cheirismos::service::config::{ConfigError, ServiceConfig};
use cheirismos::service::mcp::{McpService, McpServiceError};
use cheirismos::service::server::{DaemonLock, UnixServiceServer};
use cheirismos::store::SqliteStore;
use cheirismos::supervisor::{BackendError, Supervisor};

/// Cheirismos command-line interface.
#[derive(Parser)]
#[command(
    name = "cheirismos",
    version,
    about = "Governed physical-device operations"
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

/// Supported local service and client commands.
#[derive(Subcommand)]
enum Command {
    /// Create a private instance with distinct local operator, reviewer, and agent tokens.
    Init { instance_dir: PathBuf },
    /// Run the authenticated Unix-domain service.
    Serve { config: PathBuf },
    /// Run an official MCP stdio proxy to one already-running local service.
    Mcp {
        socket: PathBuf,
        credential: PathBuf,
    },
    /// Send one schema-validated JSON request from a file or standard input.
    Request {
        socket: PathBuf,
        credential: PathBuf,
        input: Option<PathBuf>,
    },
    /// Read a local file and import its bytes as case evidence through the service.
    Import {
        socket: PathBuf,
        credential: PathBuf,
        case: String,
        local_path: PathBuf,
    },
    /// Print the JSON Schema for closed client request families or service configuration.
    Schema {
        /// Print the private service configuration schema instead of the client request schema.
        #[arg(long)]
        service_config: bool,
    },
    /// Request configured service status through the authenticated socket.
    Status {
        socket: PathBuf,
        credential: PathBuf,
    },
}

/// CLI failures after argument parsing.
#[derive(Debug, Snafu)]
#[non_exhaustive]
enum CliError {
    #[snafu(display("local I/O failed: {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("request JSON failed: {source}"))]
    Json { source: serde_json::Error },
    #[snafu(display("service configuration failed: {source}"))]
    Config { source: ConfigError },
    #[snafu(display("local service client failed: {source}"))]
    Client { source: client::ClientError },
    #[snafu(display("invalid governed identifier: {source}"))]
    Domain {
        source: cheirismos::domain::DomainError,
    },
    #[snafu(display("artifact store failed: {source}"))]
    Evidence {
        source: cheirismos::evidence::EvidenceError,
    },
    #[snafu(display("SQLite store failed: {source}"))]
    Store {
        source: cheirismos::store::StoreError,
    },
    #[snafu(display("device backend could not open: {source}"))]
    Backend { source: BackendError },
    #[snafu(display("Unix service failed: {source}"))]
    Server {
        source: cheirismos::service::server::ServerError,
    },
    #[snafu(display("MCP service failed: {source}"))]
    Mcp { source: McpServiceError },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    initialize_stderr_tracing(&cli.global);
    match run(cli.command).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "command failed");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Init { instance_dir } => {
            let config = ServiceConfig::initialize(instance_dir)
                .map_err(|source| CliError::Config { source })?;
            println!("{}", config.instance_dir.join("service.json").display());
        }
        Command::Serve { config } => {
            let config =
                ServiceConfig::load(config).map_err(|source| CliError::Config { source })?;
            let lock = DaemonLock::acquire(&config.instance_dir)
                .map_err(|source| CliError::Server { source })?;
            let (config, api) = open_api(config)?;
            UnixServiceServer::with_daemon_lock(config, api, lock)
                .serve()
                .await
                .map_err(|source| CliError::Server { source })?;
        }
        Command::Mcp { socket, credential } => {
            McpService::new(socket, credential)
                .serve_stdio()
                .await
                .map_err(|source| CliError::Mcp { source })?;
        }
        Command::Request {
            socket,
            credential,
            input,
        } => {
            let bytes = read_input(input).await?;
            let request =
                serde_json::from_slice(&bytes).map_err(|source| CliError::Json { source })?;
            print_response(
                client::request(socket, credential, request)
                    .await
                    .map_err(|source| CliError::Client { source })?,
            );
        }
        Command::Import {
            socket,
            credential,
            case,
            local_path,
        } => {
            let bytes = tokio::fs::read(local_path)
                .await
                .map_err(|source| CliError::Io { source })?;
            let request = ServiceRequest::Evidence(EvidenceRequest::Import {
                case: cheirismos::domain::CaseId::try_from(case)
                    .map_err(|source| CliError::Domain { source })?,
                bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            });
            print_response(
                client::request(socket, credential, request)
                    .await
                    .map_err(|source| CliError::Client { source })?,
            );
        }
        Command::Schema { service_config } => {
            let schema = if service_config {
                schemars::schema_for!(ServiceConfig)
            } else {
                schemars::schema_for!(ServiceRequest)
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&schema)
                    .map_err(|source| CliError::Json { source })?
            );
        }
        Command::Status { socket, credential } => {
            print_response(
                client::request(
                    socket,
                    credential,
                    ServiceRequest::System(SystemRequest::Status {}),
                )
                .await
                .map_err(|source| CliError::Client { source })?,
            );
        }
    }
    Ok(())
}

fn open_api(config: ServiceConfig) -> Result<(ServiceConfig, Arc<ServiceApi>), CliError> {
    let artifacts = Arc::new(
        ArtifactStore::open(config.instance_dir.join("artifacts"))
            .map_err(|source| CliError::Evidence { source })?,
    );
    let store = Arc::new(
        SqliteStore::open(config.instance_dir.join("state.sqlite"))
            .map_err(|source| CliError::Store { source })?,
    );
    let backend = Arc::new(
        DeviceBackend::open(
            config.instruments.clone(),
            config.instance_dir.join("runtime"),
            Arc::clone(&artifacts),
            tokio::runtime::Handle::current(),
        )
        .map_err(|source| CliError::Backend { source })?,
    );
    let principals = config
        .credentials
        .iter()
        .map(|binding| {
            (
                binding.principal.clone(),
                cheirismos::domain::Principal {
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
    Ok((config, api))
}

async fn read_input(input: Option<PathBuf>) -> Result<Vec<u8>, CliError> {
    match input {
        Some(path) if path.as_os_str() != "-" => tokio::fs::read(path)
            .await
            .map_err(|source| CliError::Io { source }),
        _ => {
            use tokio::io::AsyncReadExt as _;
            let mut bytes = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut bytes)
                .await
                .map_err(|source| CliError::Io { source })?;
            Ok(bytes)
        }
    }
}

fn print_response(response: cheirismos::service::api::ServiceResponse) {
    match serde_json::to_string_pretty(&response) {
        Ok(encoded) => println!("{encoded}"),
        Err(error) => tracing::error!(error = %error, "response serialization failed"),
    }
}

fn initialize_stderr_tracing(global: &GlobalArgs) {
    let filter = koinon::telemetry::build_filter(global.verbosity().as_directive());
    if global.log_json() {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
    }
}
