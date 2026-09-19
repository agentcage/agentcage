//! The three files derived from `cage.yaml` on every deploy and every
//! restart: `proxy-config.yaml`, `cage-env/placeholders.env` and
//! `dns-allowlist.conf`.
//!
//! All three are regenerated rather than migrated, which is what makes
//! them safe to rewrite from a Rust binary over a Python-deployed
//! cage. And two of them are written **in place**, without the atomic
//! temp-and-rename, on purpose:
//!
//! * `placeholders.env` — "Written in place (no rename) so bind mounts
//!   keep tracking the same inode." The cage quadlet names its parent
//!   directory in a `Volume=` and the file itself in an
//!   `EnvironmentFile=`; a rename would swap the inode under a running
//!   mount.
//! * `proxy-config.yaml` — a plain `open(p, "w")` in `state.py:452`.
//!   Same reason: the egress quadlet bind-mounts it.
//!
//! So the atomic writer is *not* a blanket policy. It guards the three
//! files with concurrent readers across the trust boundary
//! (`cage.yaml`, `metadata.json`, `grants.yaml`); the bind-mounted
//! ones have a different constraint that rules it out.
//!
//! # `save_proxy_config` does two jobs
//!
//! It also calls [`Paths::save_placeholders_env`]. Both files are
//! `cage.yaml`-derived state the containers mount, and every
//! deploy/restart path that needs one needs the other, so they are
//! regenerated together to stay in lockstep. A port that split them
//! would introduce a window where the proxy's rules and the cage's
//! environment disagree about a placeholder — which is a secret that
//! does not get substituted.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use agentcage_core::config::HostProbe;
use agentcage_core::python::{repr_str, str_of};
use agentcage_core::quadlets::effective_dns_allowlist;
use agentcage_core::yaml::{self, Mapping, Value};

use crate::deployment::AgentSchema;
use crate::error::{Result, StateError};
use crate::paths::Paths;
use crate::pyfs::{expanduser, expandvars};

/// `state._PROXY_KEYS` — the twelve keys the egress addon reads.
///
/// Everything else in `cage.yaml` is stripped, so the full config is
/// never exposed inside the proxy container. Notably absent:
/// `container`, `dns_servers`, `name`, `isolation` and `ports`.
///
/// The order is `state.py`'s, but it is a `frozenset` there and the
/// filter preserves the *document's* order, not this one.
pub const PROXY_KEYS: [&str; 12] = [
    "domains",
    "secrets",
    "max_request_body",
    "entropy",
    "content_type",
    "inspectors",
    "rate_limit",
    "logging",
    "secret_injection",
    "capture",
    "protocol_relays",
    "agents",
];

impl Paths {
    /// `state.save_proxy_config` — the whitelisted subset, plus the
    /// version stamp, plus a refreshed `placeholders.env`.
    ///
    /// `version` is stamped as `agentcage_version` so the Policy API's
    /// introspection payloads can report it without depending on
    /// `AGENTCAGE_VERSION` reaching the egress environment — it is not
    /// set there on every backend. Pass [`agentcage_core::VERSION`];
    /// it is a parameter only so the state fixture can be rebuilt
    /// under the version that produced it.
    ///
    /// Returns the path written.
    ///
    /// # Errors
    ///
    /// [`StateError::Value`] if a relay's `ca_file` cannot be read or
    /// holds no certificate, plus the usual read/parse/write failures.
    pub fn save_proxy_config(&self, name: &str, version: &str) -> Result<PathBuf> {
        let raw = self.load_raw_config(name, AgentSchema::Check)?;
        let mut proxy = Mapping::new();
        if let Value::Mapping(raw) = &raw {
            // `{k: v for k, v in raw.items() if k in _PROXY_KEYS}` —
            // iteration order is the *document's*, not PROXY_KEYS'.
            for (key, value) in raw {
                if key.as_str().is_some_and(|key| PROXY_KEYS.contains(&key)) {
                    proxy.insert(key.clone(), value.clone());
                }
            }
        }
        // The Python deepcopies before the ca_file -> ca_pem rewrite so
        // the PEM cannot leak back into the in-memory raw config and
        // from there into a cage.yaml rewrite, replacing the operator's
        // path with a wall of certificate. Here the values were cloned
        // into `proxy` above, so `raw` is already untouched.
        self.resolve_relay_ca_files(&mut proxy)?;
        proxy.insert(
            Value::String("agentcage_version".to_owned()),
            Value::String(version.to_owned()),
        );

        let path = self.proxy_config_path(name);
        let document = Value::Mapping(proxy);
        let text = yaml::dump(&document).map_err(|source| StateError::Yaml {
            path: path.clone(),
            source,
        })?;
        write_in_place(&path, &text)?;
        // In lockstep, always. See the module docs.
        self.save_placeholders_env(name)?;
        Ok(path)
    }

    /// `state.resolve_relay_ca_files` — inline each relay's CA.
    ///
    /// The relay runs inside the proxy container, where a host path
    /// means nothing. Rather than bind-mount the file — which pins an
    /// inode, so a daemon that *replaces* its certificate on reinstall
    /// would be missed anyway, and which needs separate plumbing in
    /// three backends — the CLI reads it here and hands the proxy the
    /// contents. `proxy-config.yaml` is rewritten on every deploy and
    /// restart, so a rotated certificate is picked up by `cage
    /// restart` with no config edit.
    ///
    /// Mutates `proxy_cfg` in place: `ca_file` is removed (always, even
    /// when empty) and `ca_pem` added.
    ///
    /// # Errors
    ///
    /// [`StateError::Value`] with an actionable message if a declared
    /// file is missing, unreadable, or holds no PEM block. Failing at
    /// deploy beats a relay that cannot verify its upstream at 3am and
    /// says only "certificate verify failed".
    pub fn resolve_relay_ca_files(&self, proxy_cfg: &mut Mapping) -> Result<()> {
        let Some(Value::Sequence(relays)) = proxy_cfg.get_mut("protocol_relays") else {
            // `proxy_cfg.get("protocol_relays") or []` — absent, null
            // and an empty list all mean nothing to do. A non-sequence
            // would raise in Python on iteration; validation has
            // already rejected it long before here.
            return Ok(());
        };
        for relay in relays.iter_mut() {
            let Value::Mapping(relay) = relay else {
                continue;
            };
            let label = relay.get("name").map_or_else(|| "?".to_owned(), str_of);
            let Some(Value::Mapping(upstream)) = relay.get_mut("upstream") else {
                continue;
            };
            // `upstream.pop("ca_file", "")` — removed whether or not it
            // held anything, so the host path never reaches the proxy.
            let ca_file = upstream.shift_remove("ca_file").unwrap_or(Value::Null);
            if !yaml::python_bool(&ca_file) {
                continue;
            }
            let path = expanduser(&expandvars(&str_of(&ca_file)), self.home());
            let display = repr_str(&path.to_string_lossy());
            let pem = fs::read_to_string(&path).map_err(|error| {
                StateError::value(format!(
                    "protocol_relays[{label}].upstream.ca_file: \
                     cannot read {display}: {}",
                    strerror(&error)
                ))
            })?;
            if !pem.contains("-----BEGIN CERTIFICATE-----") {
                return Err(StateError::value(format!(
                    "protocol_relays[{label}].upstream.ca_file: {display} holds no \
                     PEM certificate (expected a '-----BEGIN CERTIFICATE-----' block)"
                )));
            }
            upstream.insert(Value::String("ca_pem".to_owned()), Value::String(pem));
        }
        Ok(())
    }

    /// `state.save_placeholders_env` — `ENV=PLACEHOLDER`, one per line.
    ///
    /// The cage quadlet references this file via `EnvironmentFile=`,
    /// which podman reads at container *creation*, so every restart —
    /// not only `cage update` — picks up a placeholder change. Its
    /// parent directory is bind-mounted at `/run/agentcage/env` for
    /// in-cage consumers.
    ///
    /// Derived from the *raw* stored config rather than a parsed
    /// [`agentcage_core::config::Config`], so it works in contexts
    /// where full validation would fail. Rules without a placeholder
    /// are skipped: the CLI fills omitted ones at declare time.
    ///
    /// Returns the path written. An empty file is the correct output
    /// for a cage that injects nothing, and the file is still created.
    ///
    /// # Errors
    ///
    /// As [`Paths::load_raw_config`], plus [`StateError::Io`].
    pub fn save_placeholders_env(&self, name: &str) -> Result<PathBuf> {
        let raw = self.load_raw_config(name, AgentSchema::Check)?;
        let mut text = String::new();
        for rule in injection_rules(&raw) {
            let Value::Mapping(rule) = rule else { continue };
            let (Some(env), Some(placeholder)) = (rule.get("env"), rule.get("placeholder")) else {
                continue;
            };
            // `if env and placeholder` — both have to be truthy.
            if !yaml::python_bool(env) || !yaml::python_bool(placeholder) {
                continue;
            }
            text.push_str(&str_of(env));
            text.push('=');
            text.push_str(&str_of(placeholder));
            text.push('\n');
        }
        let path = self.placeholders_env_path(name);
        write_in_place(&path, &text)?;
        Ok(path)
    }

    /// `state.save_dns_allowlist` — dnsmasq's `--servers-file`.
    ///
    /// One `server=/<domain>/<upstream>` line per (allowed-domain ×
    /// upstream-server) pair, in that nesting order. dnsmasq treats
    /// the file as a partial config, additive to the quadlet command
    /// line, and re-reads it on container start or SIGHUP — so a
    /// domain change is a file rewrite, with no unit churn and no
    /// daemon-reload.
    ///
    /// Idempotent, cheap, always safe to call. Empty when the cage is
    /// not in allowlist mode; dnsmasq is fine with an empty file.
    ///
    /// Returns the path written.
    ///
    /// # Errors
    ///
    /// As [`Paths::load_deployment_config`], plus [`StateError::Io`].
    pub fn save_dns_allowlist(&self, name: &str, host: &dyn HostProbe) -> Result<PathBuf> {
        let config = self.load_deployment_config(name, host)?;
        let mut lines: Vec<String> = Vec::new();
        for domain in effective_dns_allowlist(&config) {
            for server in &config.dns_servers {
                lines.push(format!("server=/{domain}/{server}"));
            }
        }
        // `"\n".join(lines) + ("\n" if lines else "")` — a trailing
        // newline only when there is something to terminate.
        let text = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        let path = self.dns_allowlist_path(name);
        write_in_place(&path, &text)?;
        Ok(path)
    }

    /// `state.runtime_secrets_dir` — created, at mode 0700.
    ///
    /// The `%t/agentcage/<name>/secrets` the egress quadlet mounts.
    /// The egress `ExecStartPre` stages declared secrets here at every
    /// start and the proxy reads them through the bind mount at
    /// `/home/acproxy/secrets`. tmpfs only: real values never touch
    /// persistent disk unencrypted, and it is mounted into the egress
    /// exclusively, never the cage.
    ///
    /// The chmod walks *up* — `secrets`, then `<name>`, then
    /// `agentcage` — and **stops at the first permission failure**.
    /// Once the egress has started, the secrets dir is owned by the
    /// acproxy subuid (the quadlet chowns it for in-container
    /// readability) and the host user can no longer chmod it; the
    /// modes were already set to 0700 at creation, here or by the
    /// quadlet's `umask 077; mkdir -p`. So the failure is expected and
    /// the loop breaks rather than continuing to the parents.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the directory cannot be created.
    pub fn ensure_runtime_secrets_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.runtime_secrets_dir(name);
        fs::create_dir_all(&dir).map_err(|e| StateError::io(&dir, "create directory", e))?;
        let mut candidate = dir.clone();
        for _ in 0..3 {
            if fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).is_err() {
                break;
            }
            let Some(parent) = candidate.parent().map(std::path::Path::to_path_buf) else {
                break;
            };
            candidate = parent;
        }
        Ok(dir)
    }
}

/// `si.get("rules", []) if isinstance(si, dict) else si`.
///
/// `secret_injection:` accepts two shapes — a bare list of rules, and
/// a mapping with a `rules:` key — and both reach this file.
fn injection_rules(raw: &Value) -> &[Value] {
    const NONE: &[Value] = &[];
    let Value::Mapping(raw) = raw else {
        return NONE;
    };
    match raw.get("secret_injection") {
        Some(Value::Sequence(rules)) => rules,
        Some(Value::Mapping(block)) => match block.get("rules") {
            Some(Value::Sequence(rules)) => rules,
            _ => NONE,
        },
        _ => NONE,
    }
}

/// `open(p, "w")` — truncate in place, keeping the inode.
///
/// Deliberately not [`crate::atomic::atomic_write_text`]: see the
/// module docs.
fn write_in_place(path: &std::path::Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| StateError::io(parent, "create directory", e))?;
    }
    fs::write(path, text).map_err(|e| StateError::io(path, "write", e))
}

/// `e.strerror or e` — the bare OS message, as Python formats it.
fn strerror(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        // `std`'s Display appends " (os error N)"; `strerror` does not.
        Some(_) => {
            let rendered = error.to_string();
            match rendered.find(" (os error ") {
                Some(cut) => rendered[..cut].to_owned(),
                None => rendered,
            }
        }
        None => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::PROXY_KEYS;
    use crate::paths::Paths;
    use crate::testdir::TestDir;
    use agentcage_core::config::FixedHost;
    use agentcage_core::yaml::{self, Value};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn cage(paths: &Paths, name: &str, text: &str) {
        let path = paths.stored_config_path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn the_proxy_config_holds_only_the_whitelisted_keys() {
        let dir = TestDir::new("proxy-config");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "x",
            r"name: x
isolation: container
dns_servers: [1.1.1.1]
container:
  image: localhost/x
domains:
  mode: allowlist
  allow: [a.example.com]
max_request_body: 1024
",
        );
        paths.save_proxy_config("x", "9.9.9").unwrap();

        let text = fs::read_to_string(paths.proxy_config_path("x")).unwrap();
        let Value::Mapping(cfg) = yaml::load(&text).unwrap() else {
            panic!("not a mapping");
        };
        for leaked in ["container", "dns_servers", "name", "isolation", "ports"] {
            assert!(cfg.get(leaked).is_none(), "{leaked} reached the proxy");
        }
        for key in cfg.keys() {
            let key = key.as_str().unwrap();
            assert!(
                PROXY_KEYS.contains(&key) || key == "agentcage_version",
                "unexpected key {key}"
            );
        }
        assert_eq!(
            cfg.get("agentcage_version"),
            Some(&Value::String("9.9.9".to_owned()))
        );
        // And the lockstep sibling was written too.
        assert!(paths.placeholders_env_path("x").is_file());
    }

    #[test]
    fn a_relays_ca_file_is_read_and_inlined() {
        let dir = TestDir::new("relay-ca");
        let paths = Paths::under(dir.path());
        fs::create_dir_all(paths.home()).unwrap();
        fs::write(
            paths.home().join("ca.pem"),
            "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        cage(
            &paths,
            "x",
            r"name: x
protocol_relays:
- name: mail
  type: imap
  listen: 0.0.0.0:1143
  upstream:
    host: imap.example.com
    port: 993
    ca_file: ~/ca.pem
",
        );
        paths.save_proxy_config("x", "9.9.9").unwrap();

        let text = fs::read_to_string(paths.proxy_config_path("x")).unwrap();
        let Value::Mapping(cfg) = yaml::load(&text).unwrap() else {
            panic!("not a mapping")
        };
        let Some(Value::Sequence(relays)) = cfg.get("protocol_relays") else {
            panic!("no relays")
        };
        let Value::Mapping(relay) = &relays[0] else {
            panic!("not a mapping")
        };
        let Some(Value::Mapping(upstream)) = relay.get("upstream") else {
            panic!("no upstream")
        };
        assert!(
            upstream.get("ca_file").is_none(),
            "the host path must not reach the proxy"
        );
        assert!(
            upstream
                .get("ca_pem")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );

        // And the operator's cage.yaml still says `ca_file`, not a
        // wall of PEM.
        let stored = fs::read_to_string(paths.stored_config_path("x")).unwrap();
        assert!(stored.contains("ca_file: ~/ca.pem"));
        assert!(!stored.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn an_unreadable_or_empty_ca_file_fails_the_deploy() {
        let dir = TestDir::new("relay-ca-bad");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "x",
            "name: x\nprotocol_relays:\n- name: mail\n  upstream:\n    ca_file: /nope/ca.pem\n",
        );
        let error = paths.save_proxy_config("x", "9.9.9").unwrap_err();
        assert_eq!(
            error.to_string(),
            "protocol_relays[mail].upstream.ca_file: cannot read '/nope/ca.pem': \
             No such file or directory"
        );

        fs::create_dir_all(paths.home()).unwrap();
        fs::write(paths.home().join("empty.pem"), "not a certificate\n").unwrap();
        cage(
            &paths,
            "y",
            "name: y\nprotocol_relays:\n- upstream:\n    ca_file: ~/empty.pem\n",
        );
        let error = paths.save_proxy_config("y", "9.9.9").unwrap_err();
        assert!(
            error.to_string().starts_with(&format!(
                "protocol_relays[?].upstream.ca_file: '{}/empty.pem' holds no PEM certificate",
                paths.home().display()
            )),
            "{error}"
        );
    }

    #[test]
    fn placeholders_env_accepts_both_secret_injection_shapes() {
        let dir = TestDir::new("placeholders");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "list",
            r"name: list
secret_injection:
- env: A
  placeholder: agentcage:secret:A:1
- env: B
- placeholder: agentcage:secret:C:3
",
        );
        paths.save_placeholders_env("list").unwrap();
        assert_eq!(
            fs::read_to_string(paths.placeholders_env_path("list")).unwrap(),
            "A=agentcage:secret:A:1\n"
        );

        cage(
            &paths,
            "mapping",
            r"name: mapping
secret_injection:
  rules:
  - env: A
    placeholder: agentcage:secret:A:1
",
        );
        paths.save_placeholders_env("mapping").unwrap();
        assert_eq!(
            fs::read_to_string(paths.placeholders_env_path("mapping")).unwrap(),
            "A=agentcage:secret:A:1\n"
        );

        cage(&paths, "none", "name: none\n");
        paths.save_placeholders_env("none").unwrap();
        assert_eq!(
            fs::read_to_string(paths.placeholders_env_path("none")).unwrap(),
            ""
        );
    }

    #[test]
    fn placeholders_env_keeps_its_inode_across_a_rewrite() {
        // The bind mount tracks the inode, so a rename would strand it.
        use std::os::unix::fs::MetadataExt as _;
        let dir = TestDir::new("placeholders-inode");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "x",
            "name: x\nsecret_injection:\n- env: A\n  placeholder: agentcage:secret:A:1\n",
        );
        paths.save_placeholders_env("x").unwrap();
        let before = fs::metadata(paths.placeholders_env_path("x"))
            .unwrap()
            .ino();

        cage(
            &paths,
            "x",
            "name: x\nsecret_injection:\n- env: A\n  placeholder: agentcage:secret:A:2\n",
        );
        paths.save_placeholders_env("x").unwrap();
        let after = fs::metadata(paths.placeholders_env_path("x"))
            .unwrap()
            .ino();
        assert_eq!(before, after, "the bind-mounted file was replaced");
    }

    #[test]
    fn the_dns_allowlist_is_domains_times_servers() {
        let dir = TestDir::new("dns-allowlist");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "x",
            r"name: x
container:
  image: localhost/x
dns_servers: [1.1.1.1, 9.9.9.9]
domains:
  mode: allowlist
  allow: [a.example.com, b.example.com]
  block: [bad.example.com]
",
        );
        let host = FixedHost::linux(&["1.1.1.1"]);
        paths.save_dns_allowlist("x", &host).unwrap();
        let text = fs::read_to_string(paths.dns_allowlist_path("x")).unwrap();
        assert_eq!(
            text,
            "server=/a.example.com/1.1.1.1\n\
             server=/a.example.com/9.9.9.9\n\
             server=/b.example.com/1.1.1.1\n\
             server=/b.example.com/9.9.9.9\n"
        );
        assert!(!text.contains("bad.example.com"));
    }

    #[test]
    fn an_open_mode_cage_gets_an_empty_allowlist_with_no_trailing_newline() {
        let dir = TestDir::new("dns-open");
        let paths = Paths::under(dir.path());
        cage(
            &paths,
            "x",
            "name: x\ncontainer:\n  image: localhost/x\ndns_servers: [1.1.1.1]\n",
        );
        let host = FixedHost::linux(&["1.1.1.1"]);
        paths.save_dns_allowlist("x", &host).unwrap();
        assert_eq!(
            fs::read_to_string(paths.dns_allowlist_path("x")).unwrap(),
            ""
        );
    }

    #[test]
    fn the_runtime_secrets_dir_is_0700_all_the_way_up() {
        let dir = TestDir::new("runtime-secrets");
        let paths = Paths::under(dir.path());
        let secrets = paths.ensure_runtime_secrets_dir("x").unwrap();
        for level in [
            secrets.as_path(),
            secrets.parent().unwrap(),
            secrets.parent().unwrap().parent().unwrap(),
        ] {
            let mode = fs::metadata(level).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is {mode:o}", level.display());
        }
    }
}
