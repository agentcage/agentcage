//! `agentcage-egress`: the per-cage egress proxy binary.
//!
//! ```text
//! agentcage-egress run --regular <ip>:8080 --transparent :8443 \
//!   [--reverse <cage_ip>:<p>@0.0.0.0:<p> …] \
//!   --ca-dir /home/acproxy/ca --public-cert /home/acproxy/ca/agentcage-ca.pem \
//!   --cage-name <name>
//! ```
//!
//! Started by `supervisor-egress.sh` as an unprivileged user with an empty
//! capability bounding set; it needs nothing but its listen ports (all
//! above 1024), the private CA dir and the public-cert dir. Logs go to
//! stderr. The CA is loaded (or generated, on the cage's first start), the
//! listeners are bound, and only then is the public certificate published:
//! the supervisor and the cage treat that file as the readiness signal.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use agentcage_egress::ca::{CaOrigin, CertAuthority};
use agentcage_egress::engine::{Engine, EngineOptions};
use agentcage_egress::flow::Pipeline;
use agentcage_egress::proxy::{self, ListenerSpec, Proxy, TransportSettings};

#[derive(Parser, Debug)]
#[command(name = "agentcage-egress", version = agentcage_egress::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the egress proxy.
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// The forward-proxy listener (`ip:port` or `:port`).
    #[arg(long, env = "AGENTCAGE_REGULAR_BIND", default_value = ":8080")]
    regular: String,
    /// The transparent listener (`ip:port` or `:port`).
    #[arg(long, default_value = ":8443")]
    transparent: String,
    /// A reverse listener, `<cage_ip>:<port>@<bind_ip>:<port>`; repeatable.
    #[arg(long = "reverse")]
    reverse: Vec<String>,
    /// The private CA directory (generated into on first start).
    #[arg(long, default_value = "/home/acproxy/ca")]
    ca_dir: PathBuf,
    /// Where to publish the public CA certificate.
    #[arg(long)]
    public_cert: Option<PathBuf>,
    /// The cage's name, for the CA subject.
    #[arg(long, env = "AGENTCAGE_CAGE_NAME", default_value = "agentcage")]
    cage_name: String,
    /// The ports forward-proxy targets may use (`INSPECTED_TCP_PORTS`).
    #[arg(long, env = "INSPECTED_TCP_PORTS", default_value = "80 443")]
    inspected_ports: String,
    /// The largest body buffered, in bytes.
    #[arg(long, env = "AGENTCAGE_MAX_BODY_BYTES", default_value_t = proxy::DEFAULT_MAX_BODY)]
    max_body_bytes: usize,
    /// The egress config (`/etc/agentcage/config.yaml`).
    #[arg(long, env = "AGENTCAGE_CONFIG")]
    config: Option<PathBuf>,
    /// Extra upstream trust roots (PEM). Test harnesses only.
    #[arg(long, hide = true)]
    upstream_ca: Option<PathBuf>,
}

/// The blocking pool's size (see `main`).
const MAX_BLOCKING_THREADS: usize = 64;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Run(args) = cli.command;
    // The blocking pool runs the inspector chain, injection and the
    // decider; each thread reserves a 2 MiB stack, and the supervisor's
    // `prlimit --as=2G` counts reservations, so the pool is capped well
    // below tokio's default of 512.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("agentcage-egress: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agentcage-egress: {e}");
            ExitCode::FAILURE
        }
    }
}

fn listeners(args: &RunArgs) -> Result<Vec<ListenerSpec>, String> {
    let mut specs = vec![
        ListenerSpec::Regular(proxy::parse_bind(&args.regular)?),
        ListenerSpec::Transparent(proxy::parse_bind(&args.transparent)?),
    ];
    for spec in &args.reverse {
        specs.push(proxy::parse_reverse_spec(spec).map_err(|e| e.to_string())?);
    }
    Ok(specs)
}

async fn run(args: RunArgs) -> Result<(), String> {
    let specs = listeners(&args)?;
    let settings = TransportSettings {
        max_body: args.max_body_bytes,
        inspected_ports: proxy::parse_ports(&args.inspected_ports)?,
    };
    let (ca, origin) =
        CertAuthority::load_or_create(&args.ca_dir, &args.cage_name).map_err(|e| e.to_string())?;
    eprintln!(
        "agentcage-egress {}: CA {} ({})",
        agentcage_egress::VERSION,
        ca.fingerprint_sha256(),
        match origin {
            CaOrigin::Generated => "generated",
            CaOrigin::Loaded => "loaded",
        }
    );
    let ca = Arc::new(ca);
    // Without a config (the image smoke test) the pipeline runs on an
    // empty config: listeners and CA, with the empty config's policy.
    let engine = Engine::boot(EngineOptions::from_env(args.config.clone()));
    engine.start();
    let handler = Arc::new(Pipeline::new(Arc::clone(&engine)));
    let mut proxy = Proxy::new(handler, Arc::clone(&ca), settings);
    if let Some(path) = &args.upstream_ca {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;
        let roots = CertificateDer::pem_file_iter(path)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        proxy = proxy.with_extra_upstream_roots(roots);
    }
    let bound = proxy.bind(&specs).await.map_err(|e| e.to_string())?;
    for (kind, addr) in bound.local_addrs() {
        eprintln!("agentcage-egress: listening ({kind:?}) on {addr}");
    }
    if let Some(path) = &args.public_cert {
        ca.publish(path).map_err(|e| e.to_string())?;
        eprintln!(
            "agentcage-egress: published the CA certificate to {}",
            path.display()
        );
    }
    tokio::select! {
        served = bound.run() => served.map_err(|e| e.to_string()),
        () = terminated() => {
            eprintln!("agentcage-egress: shutting down");
            engine.shutdown().await;
            Ok(())
        }
    }
}

/// SIGTERM (tini forwards the container stop) or SIGINT.
async fn terminated() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = term => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
