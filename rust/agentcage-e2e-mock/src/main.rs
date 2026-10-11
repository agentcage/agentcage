//! `agentcage-e2e-mock`: the mock upstreams `tests/e2e` runs beside each
//! cage's egress. See the library docs for what each role answers.
//!
//! ```text
//! agentcage-e2e-mock httpbin [BIND_ADDR]   httpbin stand-in + WebSocket echo on BIND_ADDR:80
//!                                          (default 0.0.0.0)
//! agentcage-e2e-mock services [LOG_DIR]    IMAP 127.0.0.1:3143, SMTP 127.0.0.1:3025,
//!                                          stub LLM 127.0.0.1:18089, TLS 0.0.0.0:443;
//!                                          logs under LOG_DIR (default /tmp/mock-log)
//! agentcage-e2e-mock probe ADDR:PORT...    exit 0 once every ADDR:PORT accepts a TCP
//!                                          connection (one attempt each, 1 s timeout)
//! ```
//!
//! Built static (`--target x86_64-unknown-linux-musl`) and bind-mounted
//! into a stock base image, so the mock needs no interpreter anywhere.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use agentcage_e2e_mock::log::{self, LogDir};
use agentcage_e2e_mock::{httpbin, imap, llm, serve_forever, smtp, tls};

const USAGE: &str =
    "usage: agentcage-e2e-mock httpbin [BIND_ADDR] | services [LOG_DIR] | probe ADDR:PORT...";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn bind(addr: &str) -> Result<TcpListener> {
    TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}").into())
}

fn httpbin(bind_addr: &str) -> Result<()> {
    let addr = format!("{bind_addr}:{}", httpbin::PORT);
    let listener = bind(&addr)?;
    eprintln!("agentcage-e2e-mock: httpbin listening on {addr}");
    serve_forever(&listener, httpbin::handle);
    Ok(())
}

fn services(log_dir: &str) -> Result<()> {
    let log = Arc::new(LogDir::create(log_dir)?);
    // Bind everything before serving anything, so a port clash fails the
    // container at once instead of leaving it half up.
    let imap_l = bind(imap::ADDR)?;
    let smtp_l = bind(smtp::ADDR)?;
    let llm_l = bind(llm::ADDR)?;
    let tls_l = bind(tls::ADDR)?;
    let (tls_config, _) = tls::server_config()?;

    let l = Arc::clone(&log);
    thread::spawn(move || serve_forever(&imap_l, move |s| imap::handle(s, &l)));
    let l = Arc::clone(&log);
    thread::spawn(move || serve_forever(&smtp_l, move |s| smtp::handle(s, &l)));
    let l = Arc::clone(&log);
    thread::spawn(move || serve_forever(&llm_l, move |s| llm::handle(s, &l)));
    eprintln!(
        "agentcage-e2e-mock: imap {} smtp {} llm {} tls {} (logs in {log_dir})",
        imap::ADDR,
        smtp::ADDR,
        llm::ADDR,
        tls::ADDR
    );
    serve_forever(&tls_l, move |s| tls::handle(s, &tls_config));
    Ok(())
}

fn probe(addrs: &[String]) -> Result<()> {
    if addrs.is_empty() {
        return Err(USAGE.into());
    }
    for addr in addrs {
        let sock: SocketAddr = addr.parse().map_err(|e| format!("{addr}: {e}"))?;
        TcpStream::connect_timeout(&sock, Duration::from_secs(1))
            .map_err(|e| format!("{addr}: {e}"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match (args.first().map(String::as_str), rest) {
        (Some("httpbin"), []) => httpbin("0.0.0.0"),
        (Some("httpbin"), [addr]) => httpbin(addr),
        (Some("services"), []) => services(log::DEFAULT_DIR),
        (Some("services"), [dir]) => services(dir),
        (Some("probe"), addrs) => probe(addrs),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agentcage-e2e-mock: {e}");
            ExitCode::FAILURE
        }
    }
}
