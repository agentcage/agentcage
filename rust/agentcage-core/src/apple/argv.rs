//! `exec_argv`, `logs_argv` and `audit_argv` — the three commands the
//! CLI dispatches through this backend.
//!
//! # `audit_argv` is not a fourth copy of the same thing
//!
//! PR D8 established that **there is no host-side `audit.jsonl` for a
//! `container` or `vm` cage**: the egress addon writes its audit trail
//! to stderr and the host reads it back out of `journalctl`. Only
//! apple-container bind-mounts the file, at
//! `<apple_state>/<cage>/logs/audit.jsonl`
//! (`agentcage_state::Paths::apple_audit_file`, the only such helper in
//! that module). So this is the one audit path in agentcage that reads
//! a file, and nothing else in the port covers it.
//!
//! Two consequences visible in the argv:
//!
//! * `since` is **ignored**. A JSONL file has no journalctl-style time
//!   index and `tail` cannot seek by time, so `cage audit --since` is
//!   applied after parsing, as `AuditFilter.since`. The parameter is
//!   still taken, to match the protocol and to keep the reason written
//!   down where someone will look for it.
//! * `follow` changes the *whole* shape rather than adding a flag:
//!   `tail -n 0 -F` (capital F, so a rotated or replaced file is
//!   reopened) against `tail -n 10000`, an over-read because not every
//!   line in the file is an audit record.
//!
//! # `exec_argv` and the setpriv wrap
//!
//! The container backend gets its privilege drop from the cage's
//! quadlet: `NoNewPrivileges=1` and a dropped `CapBnd` are inherited by
//! an exec session, so `podman exec -u 1000:1000` is enough. Apple's
//! `container exec` is not: each session is a fresh process whose caps
//! come from the container's `--cap-add` set, *not* from the
//! capsh-dropped PID 1, which left every previous `cage exec` session
//! at `CapBnd=0xa80435fb` with setuid-root binaries in the base image
//! to exploit (finding F3 of the CTF). Hence the `setpriv` wrap, and
//! hence the `sh -c` around it: `setpriv` changes uid without updating
//! `HOME` / `USER` / `LOGNAME`, and a uid-1000 process inheriting
//! root's `HOME=/root` makes `claude -p` exit 0 with no output.
//!
//! All of that is shape, and shape is argv, which is why it can be
//! pinned here without a Mac.

use std::fmt;

/// `BackendUnsupported`, the exception both argv builders raise.
///
/// Two variants because the Python has two messages and they are UX:
/// one names the services that exist, the other names the download
/// page. The order matters too — `exec_argv` validates the service
/// *before* it looks for the binary, so `cage exec --service proxy` on
/// a Mac without `container(1)` installed complains about the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppleArgvError {
    /// `cage exec --service <name>` named something that is not
    /// `cage` or `egress`.
    UnknownService(String),
    /// `apple_container.cli.container_binary()` returned `None`.
    NoContainerBinary,
}

impl fmt::Display for AppleArgvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownService(service) => write!(
                f,
                "'cage exec --service {service}' is not supported on the \
                 apple-container backend; valid services are cage / egress"
            ),
            Self::NoContainerBinary => write!(
                f,
                "Apple `container` CLI not found; install from \
                 https://github.com/apple/container/releases"
            ),
        }
    }
}

impl std::error::Error for AppleArgvError {}

/// The two addressable services, resolved to their container names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The user's workload microVM, named after the cage itself.
    Cage,
    /// The sibling running mitmproxy and dnsmasq, `<cage>-egress`.
    Egress,
}

impl Service {
    /// `exec_argv`'s dispatch: `egress`, or `cage` / the empty string,
    /// or an error.
    ///
    /// The empty string is the CLI's "no `--service` given" and means
    /// the cage, exactly as in the Python's `service in ("cage", "")`.
    ///
    /// # Errors
    ///
    /// [`AppleArgvError::UnknownService`] for anything else.
    pub fn parse(service: &str) -> Result<Self, AppleArgvError> {
        match service {
            "egress" => Ok(Self::Egress),
            "cage" | "" => Ok(Self::Cage),
            other => Err(AppleArgvError::UnknownService(other.to_owned())),
        }
    }

    /// The `container` object name for `cage`.
    #[must_use]
    pub fn target(self, cage: &str) -> String {
        match self {
            Self::Cage => cage.to_owned(),
            Self::Egress => format!("{cage}-egress"),
        }
    }
}

/// The `sh -c` program the non-root cage session runs.
///
/// `getent` is read twice rather than once because the cage user's
/// *name* and *home* are separate fields and the base image varies
/// (ubuntu / node / claude / cage). `exec env …` replaces the shell, so
/// nothing lingers between the operator's terminal and the command.
const CAGE_SETPRIV_SCRIPT: &str = "CU=$(getent passwd 1000 | cut -d: -f1) && \
CH=$(getent passwd 1000 | cut -d: -f6) && \
exec env HOME=\"$CH\" USER=\"$CU\" LOGNAME=\"$CU\" \
setpriv --reuid=1000 --regid=1000 --clear-groups \
--no-new-privs --bounding-set=-all --inh-caps=-all \
-- \"$@\"";

/// `container exec [-u <spec>] [-it] <target> [wrap…] [env…] <cmd…>`.
///
/// * `binary` — `container_binary()`. `None` is the not-installed case.
/// * `placeholders` — `services.current_placeholders(name)`, the
///   `(env, placeholder)` pairs from the *stored* cage.yaml. Decoy
///   tokens, never real values, read at call time so a secret declared
///   after the cage started is usable without a restart. Only a **cage**
///   session gets them; the egress reads the real values off its own
///   bind mount.
///
/// Note where `cmd` lands: after the wrap and after the `env` prefix,
/// not straight after the target. There is no `--` of agentcage's own
/// anywhere in the result — a separator the operator typed was consumed
/// by the parser (PR D12) and never reaches this function, and one that
/// is a genuine argument is forwarded verbatim like any other.
///
/// # Errors
///
/// [`AppleArgvError::UnknownService`] first, then
/// [`AppleArgvError::NoContainerBinary`] — the Python's order.
pub fn exec_argv(
    binary: Option<&str>,
    name: &str,
    service: &str,
    command: &[String],
    interactive: bool,
    as_root: bool,
    placeholders: &[(String, String)],
) -> Result<Vec<String>, AppleArgvError> {
    let service = Service::parse(service)?;
    let binary = binary.ok_or(AppleArgvError::NoContainerBinary)?;
    let target = service.target(name);

    // `spec` is `None` for the default cage session: no `-u` flag at
    // all, so the session enters as the image's USER (root) and setpriv
    // does the uid drop and the cap clear in one step. Handing
    // `container exec` a `-u 1000` there would drop the uid *before*
    // setpriv could use CAP_SETPCAP to clear the bounding set.
    let (spec, wrap): (Option<&str>, Vec<String>) = match (service, as_root) {
        (Service::Cage, true) => (
            Some("0:0"),
            owned(&[
                "setpriv",
                "--bounding-set=-net_admin",
                "--inh-caps=-net_admin",
                "--",
            ]),
        ),
        (Service::Cage, false) => (
            None,
            owned(&["sh", "-c", CAGE_SETPRIV_SCRIPT, "agentcage-exec-wrap"]),
        ),
        // The egress is left alone: iptables debugging there may
        // legitimately need NET_ADMIN.
        (Service::Egress, true) => (Some("0:0"), Vec::new()),
        (Service::Egress, false) => (Some("1000:1000"), Vec::new()),
    };

    // Apple's `container exec` has no `--env`, so the placeholders are
    // chained through `env(1)`. Under the setpriv wrap, `"$@"` receives
    // `[env, K=V, …, cmd…]` and `env` execs the command after the drop.
    let mut env_prefix: Vec<String> = Vec::new();
    if service == Service::Cage && !placeholders.is_empty() {
        env_prefix.push("env".to_owned());
        for (env, placeholder) in placeholders {
            env_prefix.push(format!("{env}={placeholder}"));
        }
    }

    let mut argv = vec![binary.to_owned(), "exec".to_owned()];
    if let Some(spec) = spec {
        argv.push("-u".to_owned());
        argv.push(spec.to_owned());
    }
    if interactive {
        argv.push("-it".to_owned());
    }
    argv.push(target);
    argv.extend(wrap);
    argv.extend(env_prefix);
    argv.extend(command.iter().cloned());
    Ok(argv)
}

/// `container logs [-f] <target>`.
///
/// `services` is scanned in order and the **first** recognized entry
/// wins; an unrecognized one is skipped, so `["proxy"]` — a name from
/// the legacy single-VM model — quietly tails the cage rather than
/// failing. That is the Python's behaviour, loop and all.
///
/// Apple's `container logs` accepts neither `-n` nor a level filter, so
/// `lines` and `min_level` have no parameters here; `cli.py` passes
/// them for protocol parity and the Python marks both `# noqa: ARG002`.
///
/// # Errors
///
/// [`AppleArgvError::NoContainerBinary`] when `container(1)` is absent.
pub fn logs_argv(
    binary: Option<&str>,
    name: &str,
    services: &[String],
    follow: bool,
) -> Result<Vec<String>, AppleArgvError> {
    let binary = binary.ok_or(AppleArgvError::NoContainerBinary)?;
    let mut target = name.to_owned();
    for service in services {
        if service == "egress" {
            target = format!("{name}-egress");
            break;
        }
        if service == "cage" {
            name.clone_into(&mut target);
            break;
        }
    }
    let mut argv = vec![binary.to_owned(), "logs".to_owned()];
    if follow {
        argv.push("-f".to_owned());
    }
    argv.push(target);
    Ok(argv)
}

/// `tail` over the host-side `audit.jsonl`.
///
/// `audit_path` is `Paths::apple_audit_file(name)`. It needs no
/// `container` binary: the file is a host path, bind-mounted out of the
/// egress microVM, which is the whole reason this backend's audit works
/// differently from the other two (see the module docs).
///
/// `since` has no parameter for the reason the module docs give — the
/// Python takes it only to satisfy the protocol and never reads it.
#[must_use]
pub fn audit_argv(audit_path: &str, follow: bool) -> Vec<String> {
    let mut argv = owned(&["tail", "-n"]);
    argv.push(if follow { "0" } else { "10000" }.to_owned());
    if follow {
        argv.push("-F".to_owned());
    }
    argv.push(audit_path.to_owned());
    argv
}

fn owned(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::{AppleArgvError, Service, audit_argv, exec_argv, logs_argv};

    const BIN: Option<&str> = Some("/usr/local/bin/container");

    fn cmd(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn an_unknown_service_is_refused_before_the_binary_is_looked_for() {
        let error = exec_argv(None, "demo", "proxy", &cmd(&["ls"]), false, false, &[])
            .expect_err("unknown service");
        assert_eq!(error, AppleArgvError::UnknownService("proxy".to_owned()));
        assert!(
            error
                .to_string()
                .contains("valid services are cage / egress")
        );
    }

    #[test]
    fn a_missing_container_cli_names_the_download_page() {
        let error =
            exec_argv(None, "demo", "cage", &cmd(&["ls"]), false, false, &[]).expect_err("no cli");
        assert_eq!(error, AppleArgvError::NoContainerBinary);
        assert!(error.to_string().contains("github.com/apple/container"));
    }

    #[test]
    fn the_empty_service_is_the_cage() {
        assert_eq!(Service::parse("").expect("empty"), Service::Cage);
        assert_eq!(Service::parse("cage").expect("cage"), Service::Cage);
        assert_eq!(Service::parse("egress").expect("egress"), Service::Egress);
    }

    /// The property PR D12 proved for the container backend, restated
    /// here: `cage exec foo -- ls -la` and the separator-less spelling
    /// parse to the same `command`, so they must build the same argv —
    /// and neither carries a `--` of agentcage's own.
    #[test]
    fn the_separator_never_reaches_the_argv() {
        let with =
            exec_argv(BIN, "demo", "cage", &cmd(&["ls", "-la"]), false, false, &[]).expect("argv");
        let without =
            exec_argv(BIN, "demo", "", &cmd(&["ls", "-la"]), false, false, &[]).expect("argv");
        assert_eq!(with, without);
        // The only `--` in a default cage session is the one *inside*
        // the setpriv script, which is a single argument, not a bare
        // separator.
        assert!(!with.iter().any(|part| part == "--"), "{with:?}");
        assert_eq!(with.last().expect("last"), "-la");
    }

    /// A `--` the operator meant as an argument is forwarded verbatim.
    #[test]
    fn a_double_dash_inside_the_command_is_forwarded() {
        let argv = exec_argv(
            BIN,
            "demo",
            "cage",
            &cmd(&["git", "log", "--", "src"]),
            false,
            false,
            &[],
        )
        .expect("argv");
        let tail: Vec<&String> = argv.iter().rev().take(4).rev().collect();
        assert_eq!(
            tail,
            [
                &"git".to_owned(),
                &"log".to_owned(),
                &"--".to_owned(),
                &"src".to_owned()
            ]
        );
    }

    #[test]
    fn only_a_cage_session_gets_the_placeholders() {
        let pairs = [("KEY".to_owned(), "sk-decoy".to_owned())];
        let cage =
            exec_argv(BIN, "demo", "cage", &cmd(&["sh"]), false, false, &pairs).expect("argv");
        assert!(
            cage.windows(2)
                .any(|w| w[0] == "env" && w[1] == "KEY=sk-decoy")
        );
        let egress =
            exec_argv(BIN, "demo", "egress", &cmd(&["sh"]), false, false, &pairs).expect("argv");
        assert!(!egress.iter().any(|part| part == "env"), "{egress:?}");
        assert_eq!(egress[2], "-u");
        assert_eq!(egress[3], "1000:1000");
    }

    #[test]
    fn logs_pick_the_first_recognized_service() {
        let cases: [(&[&str], &str); 5] = [
            (&[], "demo"),
            (&["cage"], "demo"),
            (&["egress"], "demo-egress"),
            (&["cage", "egress"], "demo"),
            (&["proxy"], "demo"),
        ];
        for (services, target) in cases {
            let argv = logs_argv(BIN, "demo", &cmd(services), false).expect("argv");
            assert_eq!(argv.last().expect("target"), target, "{services:?}");
        }
        let followed = logs_argv(BIN, "demo", &cmd(&["egress"]), true).expect("argv");
        assert_eq!(followed[2], "-f");
    }

    #[test]
    fn audit_follows_by_reopening_the_file() {
        assert_eq!(
            audit_argv("/s/demo/logs/audit.jsonl", false),
            cmd(&["tail", "-n", "10000", "/s/demo/logs/audit.jsonl"])
        );
        assert_eq!(
            audit_argv("/s/demo/logs/audit.jsonl", true),
            cmd(&["tail", "-n", "0", "-F", "/s/demo/logs/audit.jsonl"])
        );
    }
}
