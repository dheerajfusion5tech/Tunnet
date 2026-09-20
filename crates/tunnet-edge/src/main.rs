mod acme;
mod agent_accept;
mod control;
mod https;
mod metrics;
mod registry;
mod tcp;
mod transport;
mod usage;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tunnet_common::EDGE_ALPN;

use crate::agent_accept::AuthStore;
use crate::metrics::EdgeMetrics;
use crate::registry::TunnelRegistry;
use crate::tcp::TcpMappingManager;

#[derive(Parser, Debug)]
#[command(name = "tunnet-edge", about = "Tunnet public edge")]
struct Cli {
    #[arg(long, env = "TUNNET_JSON_LOGS")]
    json_logs: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the edge (HTTPS termination + agent reverse-tunnel acceptor)
    Run(RunArgs),
    /// Register with the control plane using a one-time dashboard token, then run
    Register(RegisterArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    #[arg(long, env = "CONTROL_PLANE_URL")]
    control_url: Option<String>,
    /// Edge auth / registration token (Bearer)
    #[arg(long, env = "TUNNET_EDGE_TOKEN")]
    token: Option<String>,
    #[arg(long, env = "TUNNET_EDGE_HTTPS_BIND", default_value = "0.0.0.0:443")]
    https_bind: String,
    #[arg(long, env = "TUNNET_EDGE_CERT")]
    cert: Option<PathBuf>,
    #[arg(long, env = "TUNNET_EDGE_KEY")]
    key: Option<PathBuf>,
    /// Persist identity across restarts
    #[arg(long, env = "TUNNET_EDGE_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Allow any auth token when AuthStore is empty (dev only)
    #[arg(long, env = "TUNNET_EDGE_OPEN_AUTH")]
    open_auth: bool,
    /// Let's Encrypt contact email (optional but recommended)
    #[arg(long, env = "TUNNET_EDGE_ACME_EMAIL")]
    acme_email: Option<String>,
    /// Comma-separated hostnames for ACME HTTP-01 (not wildcards - use --cert/--key for those)
    #[arg(long, env = "TUNNET_EDGE_ACME_DOMAIN")]
    acme_domain: Option<String>,
    /// Directory for ACME account + cert cache (default: <state_dir>/acme)
    #[arg(long, env = "TUNNET_EDGE_ACME_DIR")]
    acme_dir: Option<PathBuf>,
    /// Use Let's Encrypt staging environment
    #[arg(long, env = "TUNNET_EDGE_ACME_STAGING")]
    acme_staging: bool,
    /// Internal bind for /metrics and /ready
    #[arg(
        long,
        env = "TUNNET_EDGE_METRICS_BIND",
        default_value = "127.0.0.1:9090"
    )]
    metrics_bind: String,
}

#[derive(Parser, Debug)]
struct RegisterArgs {
    #[arg(long, env = "CONTROL_PLANE_URL")]
    control_url: String,
    #[arg(long, env = "TUNNET_EDGE_TOKEN")]
    token: String,
    #[arg(long, env = "TUNNET_EDGE_HTTPS_BIND", default_value = "0.0.0.0:443")]
    https_bind: String,
    #[arg(long, env = "TUNNET_EDGE_CERT")]
    cert: Option<PathBuf>,
    #[arg(long, env = "TUNNET_EDGE_KEY")]
    key: Option<PathBuf>,
    #[arg(long, env = "TUNNET_EDGE_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[arg(long, env = "TUNNET_EDGE_ACME_EMAIL")]
    acme_email: Option<String>,
    /// Comma-separated hostnames for ACME HTTP-01 (not wildcards - use --cert/--key for those)
    #[arg(long, env = "TUNNET_EDGE_ACME_DOMAIN")]
    acme_domain: Option<String>,
    #[arg(long, env = "TUNNET_EDGE_ACME_DIR")]
    acme_dir: Option<PathBuf>,
    #[arg(long, env = "TUNNET_EDGE_ACME_STAGING")]
    acme_staging: bool,
    #[arg(
        long,
        env = "TUNNET_EDGE_METRICS_BIND",
        default_value = "127.0.0.1:9090"
    )]
    metrics_bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    init_logging(cli.json_logs);

    match cli.command {
        Command::Run(args) => run(RunConfig::from_run(args)).await,
        Command::Register(args) => {
            run(RunConfig {
                control_url: Some(args.control_url),
                token: Some(args.token),
                https_bind: args.https_bind,
                cert: args.cert,
                key: args.key,
                state_dir: args.state_dir,
                open_auth: false,
                acme_email: args.acme_email,
                acme_domain: args.acme_domain,
                acme_dir: args.acme_dir,
                acme_staging: args.acme_staging,
                metrics_bind: args.metrics_bind,
            })
            .await
        }
    }
}

struct RunConfig {
    control_url: Option<String>,
    token: Option<String>,
    https_bind: String,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    open_auth: bool,
    acme_email: Option<String>,
    acme_domain: Option<String>,
    acme_dir: Option<PathBuf>,
    acme_staging: bool,
    metrics_bind: String,
}

impl RunConfig {
    fn from_run(a: RunArgs) -> Self {
        Self {
            control_url: a.control_url,
            token: a.token,
            https_bind: a.https_bind,
            cert: a.cert,
            key: a.key,
            state_dir: a.state_dir,
            open_auth: a.open_auth,
            acme_email: a.acme_email,
            acme_domain: a.acme_domain,
            acme_dir: a.acme_dir,
            acme_staging: a.acme_staging,
            metrics_bind: a.metrics_bind,
        }
    }
}

fn init_logging(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tunnet_edge=debug"));
    let sub = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        sub.json().init();
    } else {
        sub.init();
    }
}

async fn run(cfg: RunConfig) -> anyhow::Result<()> {
    let metrics = EdgeMetrics::new().context("edge metrics")?;
    metrics::spawn_metrics_server(metrics.clone(), cfg.metrics_bind.clone());

    let state_dir = cfg.state_dir.clone().unwrap_or_else(|| {
        let base = std::env::var("LOCALAPPDATA")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".into());
        PathBuf::from(base).join("tunnet-edge")
    });
    std::fs::create_dir_all(&state_dir)?;
    let key_path = state_dir.join("edge.key");

    let secret = load_or_create_secret(&key_path)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![EDGE_ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint")?;

    let endpoint_id = format!("{}", endpoint.id());
    tracing::info!(%endpoint_id, "edge iroh endpoint online");

    let registry = TunnelRegistry::new();
    let auth = AuthStore::default();
    let tcp_mgr = TcpMappingManager::new();
    if cfg.open_auth {
        tracing::warn!("open-auth enabled - accepting first-seen tokens (dev only)");
    }

    let _router = agent_accept::spawn_acceptor(
        endpoint.clone(),
        registry.clone(),
        auth.clone(),
        metrics.clone(),
    );

    let (cert_pem, key_pem) = match load_tls_material(&cfg, &state_dir, &metrics).await {
        Ok(v) => v,
        Err(e) => {
            if cfg.acme_domain.is_some() {
                metrics.acme_failure();
            }
            return Err(e);
        }
    };
    let cert_valid_until = https::cert_valid_until(&cert_pem);
    if let Some(ref until) = cert_valid_until {
        tracing::info!(cert_valid_until = %until, "TLS certificate loaded");
    }
    let acceptor = https::build_tls_acceptor(&cert_pem, &key_pem)?;
    let bind: SocketAddr = cfg.https_bind.parse().context("parse https-bind")?;

    let control_client = if let (Some(control_url), Some(token)) = (&cfg.control_url, &cfg.token) {
        let client =
            control::ControlClient::new(control_url.clone(), token.clone(), metrics.clone())?;
        match client.register(&endpoint_id, None).await {
            Ok(reg) => {
                metrics.registration_ok(true);
                tracing::info!(
                    edge_id = %reg.edge_id,
                    name = %reg.name,
                    domain = %reg.domain,
                    metering = reg.metering_enabled,
                    "registered with control plane"
                );
            }
            Err(e) => {
                metrics.registration_ok(false);
                tracing::warn!(?e, "control plane register failed - continuing offline");
            }
        }
        tcp_mgr.set_control(Some(client.clone()));
        control::spawn_heartbeat_loop(
            client.clone(),
            endpoint_id.clone(),
            registry.clone(),
            auth.clone(),
            tcp_mgr.clone(),
            cert_valid_until,
            metrics.clone(),
        );
        Some(client)
    } else {
        tracing::info!("no control URL/token - running without CP registration");
        None
    };

    println!("Tunnet edge ready");
    println!("  endpoint  {endpoint_id}");
    println!("  https     {bind}");
    println!("  metrics   {}", cfg.metrics_bind);
    println!("  state     {}", state_dir.display());
    if cfg.acme_domain.is_some() {
        println!("  acme      HTTP-01 (port 80)");
    }

    tokio::select! {
        r = https::serve_https(bind, acceptor, registry, auth, control_client, metrics) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("ctrl-c, shutting down"),
    }

    endpoint.close().await;
    Ok(())
}

fn load_or_create_secret(path: &PathBuf) -> anyhow::Result<SecretKey> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            anyhow::bail!("edge.key must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(SecretKey::from_bytes(&arr));
    }
    let secret = SecretKey::generate();
    tunnet_common::persistence::atomic_write_private(path, secret.to_bytes())?;
    Ok(secret)
}

async fn load_tls_material(
    cfg: &RunConfig,
    state_dir: &std::path::Path,
    metrics: &EdgeMetrics,
) -> anyhow::Result<(String, String)> {
    match (&cfg.cert, &cfg.key, &cfg.acme_domain) {
        (Some(c), Some(k), _) => {
            let cert =
                std::fs::read_to_string(c).with_context(|| format!("read cert {}", c.display()))?;
            let key =
                std::fs::read_to_string(k).with_context(|| format!("read key {}", k.display()))?;
            Ok((cert, key))
        }
        (None, None, Some(domains_raw)) => {
            let domains = acme::AcmeConfig::parse_domains(domains_raw)?;
            let dir = cfg
                .acme_dir
                .clone()
                .unwrap_or_else(|| acme::default_acme_dir(state_dir));
            let acme_cfg = acme::AcmeConfig {
                email: cfg.acme_email.clone(),
                domains,
                dir,
                staging: cfg.acme_staging,
                http_bind: "0.0.0.0:80".parse()?,
            };
            match acme::obtain_or_load(&acme_cfg).await {
                Ok(v) => Ok(v),
                Err(e) => {
                    metrics.acme_failure();
                    Err(e)
                }
            }
        }
        (None, None, None) => {
            tracing::warn!(
                "no --cert/--key or --acme-domain - generating ephemeral self-signed cert"
            );
            https::generate_dev_cert("tunnet-edge.local")
        }
        _ => {
            anyhow::bail!(
                "both --cert and --key are required together (or use --acme-domain alone)"
            )
        }
    }
}
