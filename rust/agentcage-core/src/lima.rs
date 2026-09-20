//! `lima/provisioning.py` — the Lima YAML a `vm` cage is created from.
//!
//! The first half of the `vm` backend (RUST-PORT-PLAN.md Track E, PR
//! E1): everything that turns a `cage.yaml` into the text `limactl
//! create` is handed. No subprocess runs here, so the whole of it is
//! checkable on a Linux CI runner that has never seen `limactl` — which
//! is the split the plan draws through this backend, and the reason the
//! execution half (E4) is a separate PR.
//!
//! # Two host facts arrive as arguments
//!
//! The Python reads them from the process:
//!
//! ```python
//! vm_type = "vz" if platform.system() == "Darwin" else "qemu"
//! provision_script = provision_tmpl.render(
//!     lima_user=pwd.getpwuid(os.getuid()).pw_name,
//! )
//! ```
//!
//! Both are in [`LimaFacts`] instead. `agentcage-core` does no I/O, and
//! the user name in particular is a *password-database* lookup, not an
//! environment read — the Python's comment is explicit that
//! `getpass.getuser()` would be wrong because it trusts `$USER` and can
//! disagree under `sudo`. Making it a parameter also lets the fixture
//! generator and the Rust test agree on one frozen name instead of
//! pinning whoever ran them.
//!
//! # The filesystem questions go through [`QuadletHost`]
//!
//! `_extra_mounts_for_volumes` calls `realpath`, `exists` and `isdir`
//! on every volume source, and *skips* the ones that are missing or are
//! files. Those answers change the emitted YAML, so they cannot be
//! guessed: they come from the same trait the quadlet renderer already
//! asks, which the golden harness answers from a hermetic tree.
//!
//! # What is deliberately not here
//!
//! `provision.sh.j2` itself. It installs podman and its network stack
//! and **no Python** — §2.4's invariant — and the port renders it
//! unmodified, exactly as it renders every other `.j2` source.

use serde::Serialize;

use crate::config::{Config, ConfigError};
use crate::python::repr_str;
use crate::quadlets::{QuadletHost, expanduser, expandvars, templates};
use crate::volume_mounts::{
    is_non_persistent_volume, validate_non_persistent_volume, volume_options,
};

/// Directories that must never be shared into the guest, even when a
/// user volume points inside one.
///
/// `_BLOCKED_MOUNT_DIRS`. Checked as resolved real-path prefixes under
/// the *host* home, and checked before the existence test so that an
/// explicit attempt to mount `~/.ssh` always fails loudly rather than
/// being skipped as "does not exist" on a machine that has no such
/// directory.
pub const BLOCKED_MOUNT_DIRS: [&str; 5] = [".ssh", ".gnupg", ".aws", ".kube", ".docker"];

/// One `portForwards` entry.
///
/// Field names are the template's, not Python's dict keys: the template
/// reads `pf.guest_port` / `pf.host_port` / `pf.host_bind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PortForward {
    /// The host address Lima binds, `127.0.0.1` unless the spec names
    /// one.
    pub host_bind: String,
    /// The host-side port.
    pub host_port: i64,
    /// The guest-side port.
    pub guest_port: i64,
}

/// One extra `mounts` entry, derived from a user volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExtraMount {
    /// The resolved host directory virtiofs shares.
    pub location: String,
    /// Whether the guest may write through it.
    pub writable: bool,
}

/// The two host facts the Python reads from the process.
#[derive(Clone, Copy, Debug)]
pub struct LimaFacts<'a> {
    /// `platform.system()` — `"Darwin"` selects the `vz` driver.
    pub system: &'a str,
    /// The guest user name, which Lima mirrors from the host's passwd
    /// entry for the invoking uid.
    pub lima_user: &'a str,
}

/// A rendered Lima config, plus what the Python printed on the way.
#[derive(Clone, Debug, Default)]
pub struct LimaConfig {
    /// The YAML `limactl create` is handed.
    pub yaml: String,
    /// `click.echo(..., err=True)` lines, in order, each without its
    /// trailing newline. Returned rather than printed: this crate has
    /// no stdout.
    pub warnings: Vec<String>,
}

/// The context `lima.yaml.j2` is rendered with.
#[derive(Debug, Serialize)]
struct LimaContext<'a> {
    name: &'a str,
    vm_type: &'a str,
    vcpus: i64,
    mem_gb: i64,
    provision_script: String,
    port_forwards: Vec<PortForward>,
    extra_mounts: Vec<ExtraMount>,
}

/// The context `provision.sh.j2` is rendered with.
#[derive(Debug, Serialize)]
struct ProvisionContext<'a> {
    lima_user: &'a str,
}

/// `int(text)` for a port field, with Python's error message.
///
/// The Python does not guard these conversions, so a spec that reaches
/// here with a non-numeric part raises `ValueError` out of `int()` and
/// the CLI shows its message. Reproduced rather than replaced, because
/// `cage create` puts it in front of a user.
///
/// Python's `int()` tolerates surrounding whitespace and a leading sign;
/// it also tolerates underscores (`1_0`), which this does not. A port
/// spec containing an underscore is rejected by config validation long
/// before it reaches this function, so the divergence is unreachable
/// through the CLI.
fn python_int(text: &str) -> Result<i64, ConfigError> {
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    trimmed.parse::<i64>().map_err(|_| {
        ConfigError::value(format!(
            "invalid literal for int() with base 10: {}",
            repr_str(text)
        ))
    })
}

/// `_parse_port_forwards` — Docker-style port specs into Lima entries.
///
/// `HOST:GUEST` binds `127.0.0.1`; `BIND:HOST:GUEST` binds what it says.
///
/// # Errors
///
/// [`ConfigError::Value`] for a spec with the wrong number of parts, or
/// a part that is not an integer.
pub fn parse_port_forwards(ports: &[String]) -> Result<Vec<PortForward>, ConfigError> {
    let mut out = Vec::with_capacity(ports.len());
    for spec in ports {
        let fields: Vec<&str> = spec.split(':').collect();
        let (host_bind, host_port, guest_port) = match fields.as_slice() {
            [host, guest] => ("127.0.0.1", *host, *guest),
            [bind, host, guest] => (*bind, *host, *guest),
            _ => {
                return Err(ConfigError::value(format!(
                    "Invalid port spec {}: expected HOST:GUEST or BIND:HOST:GUEST",
                    repr_str(spec)
                )));
            }
        };
        out.push(PortForward {
            host_bind: host_bind.to_owned(),
            host_port: python_int(host_port)?,
            guest_port: python_int(guest_port)?,
        });
    }
    Ok(out)
}

/// Whether `path` is `prefix` or sits under it.
///
/// `p == prefix or p.startswith(prefix + os.sep)` — the `+ os.sep` is
/// what keeps `~/.ssh-backup` from matching `~/.ssh`.
fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// `_extra_mounts_for_volumes` — the virtiofs shares a cage's volumes
/// need.
///
/// Each `host:container[:opts]` spec needs its *host* side visible in
/// the guest. The host part is expanded (`~` and `${VARS}` both),
/// resolved, and then either emitted, skipped, or refused:
///
/// * refused — it resolves under one of [`BLOCKED_MOUNT_DIRS`];
/// * skipped silently — it is already inside the two default mounts, it
///   is a duplicate, or it is a regular file (Lima virtiofs-shares
///   directories only, and `limactl create` fails fatally on a file
///   source; the quadlet layer stages a copy of those instead);
/// * skipped **with a warning** — it did not expand, or does not exist.
///   Lima only warns about a missing mount source, but the guest then
///   never finishes starting, so a bogus mount must never be emitted.
///
/// # Errors
///
/// [`ConfigError::Value`] for a blocked source, or for an `np` spec
/// whose other options cannot compose with it.
pub fn extra_mounts_for_volumes(
    volumes: &[String],
    host: &dyn QuadletHost,
) -> Result<(Vec<ExtraMount>, Vec<String>), ConfigError> {
    let home = host.realpath(&expanduser("~", host));
    let config_dir = host.realpath(&expanduser("~/.config/agentcage", host));
    let data_dir = host.realpath(&expanduser("~/.local/share/agentcage", host));

    let mut seen: Vec<String> = Vec::new();
    let mut mounts: Vec<ExtraMount> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for volume in volumes {
        validate_non_persistent_volume(volume).map_err(ConfigError::value)?;
        // `vol.split(":")[0]` — the first field, even when the spec is
        // malformed in some other way.
        let host_part = volume.split(':').next().unwrap_or("");
        let expanded = expandvars(&expanduser(host_part, host), host);
        let host_path = host.realpath(&expanded);

        for blocked in BLOCKED_MOUNT_DIRS {
            let blocked_path = format!("{}/{blocked}", home.trim_end_matches('/'));
            if under(&host_path, &blocked_path) {
                return Err(ConfigError::value(format!(
                    "volume host path {} resolves under ~/{blocked} which must \
                     not be exposed to the VM",
                    repr_str(host_part)
                )));
            }
        }

        // Already covered by the two default mounts.
        if under(&host_path, &config_dir) || under(&host_path, &data_dir) {
            continue;
        }

        if host_path.contains('$') || !host.exists(&host_path) {
            warnings.push(format!(
                "warning: not mounting {} into the VM (host path does not exist)",
                repr_str(host_part)
            ));
            continue;
        }

        if !host.is_dir(&host_path) {
            continue;
        }

        if seen.iter().any(|s| s == &host_path) {
            continue;
        }
        seen.push(host_path.clone());

        // Read-only unless the spec says `rw`. An inline `np` bind is
        // only an overlay lowerdir for podman in the guest, so it is
        // shared read-only with Lima however the cage sees it.
        let options = volume_options(volume);
        let writable = options.contains(&"rw") && !is_non_persistent_volume(volume);

        mounts.push(ExtraMount {
            location: host_path,
            writable,
        });
    }

    Ok((mounts, warnings))
}

/// `math.ceil(mem_mb / 1024)`.
///
/// Integer arithmetic rather than a float divide: the Python's operands
/// are ints and the quotient is exact, so `f64` would only introduce a
/// rounding question at sizes no VM has. Guarded for a non-positive
/// value, which config validation rejects but which a hand-built
/// `Config` could still carry.
fn mem_gb(mem_mb: i64) -> i64 {
    if mem_mb <= 0 {
        return 0;
    }
    mem_mb.div_euclid(1024) + i64::from(mem_mb.rem_euclid(1024) != 0)
}

/// `generate_lima_config` — the YAML for one cage.
///
/// # Errors
///
/// [`ConfigError::Value`] from the port specs or the volume sources, and
/// for a template that fails to render — which for these two embedded
/// sources means a bug in this crate rather than bad input.
pub fn generate_lima_config(
    config: &Config,
    facts: &LimaFacts<'_>,
    host: &dyn QuadletHost,
) -> Result<LimaConfig, ConfigError> {
    // Lima's `vz` driver is Virtualization.framework, so it is macOS
    // only; everything else gets QEMU.
    let vm_type = if facts.system == "Darwin" {
        "vz"
    } else {
        "qemu"
    };

    let provision_script = templates::render_untrimmed(
        "lima/provision.sh.j2",
        minijinja::Value::from_serialize(ProvisionContext {
            lima_user: facts.lima_user,
        }),
    )
    .map_err(ConfigError::value)?;

    let port_forwards = parse_port_forwards(&config.container.ports)?;
    let (extra_mounts, warnings) = extra_mounts_for_volumes(&config.container.volumes, host)?;

    let yaml = templates::render_untrimmed(
        "lima/lima.yaml.j2",
        minijinja::Value::from_serialize(LimaContext {
            name: &config.name,
            vm_type,
            vcpus: config.vm.vcpus,
            mem_gb: mem_gb(config.vm.mem_mb),
            provision_script,
            port_forwards,
            extra_mounts,
        }),
    )
    .map_err(ConfigError::value)?;

    Ok(LimaConfig { yaml, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`QuadletHost`] over a declared world: a home, a set of
    /// directories, a set of files, and an environment.
    #[derive(Debug, Default)]
    struct World {
        home: String,
        dirs: Vec<String>,
        files: Vec<String>,
        env: Vec<(String, String)>,
    }

    impl QuadletHost for World {
        fn env_var(&self, name: &str) -> Option<String> {
            self.env
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }

        fn realpath(&self, path: &str) -> String {
            path.to_owned()
        }

        fn exists(&self, path: &str) -> bool {
            self.dirs.iter().any(|d| d == path) || self.files.iter().any(|f| f == path)
        }

        fn is_dir(&self, path: &str) -> bool {
            self.dirs.iter().any(|d| d == path)
        }

        fn stage_vm_file_volume(&self, _source: &str, _deploy: &str) -> Result<String, String> {
            unreachable!("not reached by the lima renderer")
        }

        fn detect_default_creds_scope(&self) -> Option<String> {
            None
        }

        fn home(&self) -> String {
            self.home.clone()
        }
    }

    fn world() -> World {
        World {
            home: "/home/cageuser".to_owned(),
            dirs: vec![
                "/home/cageuser".to_owned(),
                "/home/cageuser/.config/agentcage".to_owned(),
                "/home/cageuser/.local/share/agentcage".to_owned(),
                "/home/cageuser/project".to_owned(),
                "/home/cageuser/data".to_owned(),
            ],
            files: vec!["/home/cageuser/.claude.json".to_owned()],
            env: vec![(
                "PROJECT_DIR".to_owned(),
                "/home/cageuser/project".to_owned(),
            )],
        }
    }

    #[test]
    fn two_part_spec_binds_loopback() {
        let ports = vec!["8080:80".to_owned()];
        assert_eq!(
            parse_port_forwards(&ports).expect("parses"),
            vec![PortForward {
                host_bind: "127.0.0.1".to_owned(),
                host_port: 8080,
                guest_port: 80,
            }]
        );
    }

    #[test]
    fn three_part_spec_keeps_its_bind() {
        let ports = vec!["0.0.0.0:443:443".to_owned()];
        assert_eq!(
            parse_port_forwards(&ports).expect("parses")[0].host_bind,
            "0.0.0.0"
        );
    }

    #[test]
    fn one_part_spec_is_the_python_message() {
        let ports = vec!["80".to_owned()];
        let error = parse_port_forwards(&ports).expect_err("refuses");
        assert_eq!(
            error.message(),
            "Invalid port spec '80': expected HOST:GUEST or BIND:HOST:GUEST"
        );
    }

    #[test]
    fn non_numeric_port_is_the_int_message() {
        let ports = vec!["http:80".to_owned()];
        let error = parse_port_forwards(&ports).expect_err("refuses");
        assert_eq!(
            error.message(),
            "invalid literal for int() with base 10: 'http'"
        );
    }

    #[test]
    fn blocked_directory_is_refused() {
        let volumes = vec!["~/.ssh:/keys:ro".to_owned()];
        let error = extra_mounts_for_volumes(&volumes, &world()).expect_err("refuses");
        assert_eq!(
            error.message(),
            "volume host path '~/.ssh' resolves under ~/.ssh which must not be \
             exposed to the VM"
        );
    }

    #[test]
    fn blocked_check_precedes_the_existence_check() {
        // `~/.kube` is not in the world's directory list, so an
        // existence-first implementation would skip it with a warning.
        let volumes = vec!["~/.kube:/kube:ro".to_owned()];
        assert!(extra_mounts_for_volumes(&volumes, &world()).is_err());
    }

    #[test]
    fn default_mounts_are_not_repeated() {
        let volumes = vec!["~/.local/share/agentcage/x:/x:rw".to_owned()];
        let (mounts, warnings) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert!(mounts.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn rw_is_writable_and_np_is_not() {
        let volumes = vec![
            "/home/cageuser/project:/workspace:rw".to_owned(),
            "/home/cageuser/data:/data:rw,np".to_owned(),
        ];
        let (mounts, _) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert_eq!(
            mounts,
            vec![
                ExtraMount {
                    location: "/home/cageuser/project".to_owned(),
                    writable: true,
                },
                ExtraMount {
                    location: "/home/cageuser/data".to_owned(),
                    writable: false,
                },
            ]
        );
    }

    #[test]
    fn a_file_source_is_skipped_without_a_warning() {
        let volumes = vec!["/home/cageuser/.claude.json:/root/.claude.json:rw".to_owned()];
        let (mounts, warnings) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert!(mounts.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_missing_source_warns_in_the_python_words() {
        let volumes = vec!["/home/cageuser/nope:/x:rw".to_owned()];
        let (mounts, warnings) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert!(mounts.is_empty());
        assert_eq!(
            warnings,
            vec![
                "warning: not mounting '/home/cageuser/nope' into the VM (host \
                 path does not exist)"
            ]
        );
    }

    #[test]
    fn an_unexpanded_variable_warns_rather_than_reaching_lima() {
        let volumes = vec!["${NOT_SET}:/workspace:rw".to_owned()];
        let (mounts, warnings) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert!(mounts.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn a_set_variable_expands() {
        let volumes = vec!["${PROJECT_DIR}:/workspace:rw".to_owned()];
        let (mounts, _) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert_eq!(mounts[0].location, "/home/cageuser/project");
    }

    #[test]
    fn the_same_source_twice_is_one_mount() {
        let volumes = vec![
            "/home/cageuser/project:/a:ro".to_owned(),
            "/home/cageuser/project:/b:ro".to_owned(),
        ];
        let (mounts, _) = extra_mounts_for_volumes(&volumes, &world()).expect("renders");
        assert_eq!(mounts.len(), 1);
    }

    #[test]
    fn memory_rounds_up() {
        assert_eq!(mem_gb(4096), 4);
        assert_eq!(mem_gb(1500), 2);
        assert_eq!(mem_gb(1), 1);
        assert_eq!(mem_gb(0), 0);
    }
}
