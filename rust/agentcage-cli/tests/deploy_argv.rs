//! argv assertions over the deploy sequence, with no podman in sight.
//!
//! `services.build_and_deploy` is the one function PR D6 exists for, and
//! its acceptance check is an e2e run against real podman — which is the
//! right check and a bad regression suite: five minutes, a live daemon,
//! and a failure that says "the cage did not come up" rather than "the
//! volume unit is restarted after the network unit".
//!
//! So the same path runs here against [`FakeRunner`], and what is
//! asserted is the argv, in order. Three things that would otherwise be
//! invisible until a cage failed to boot:
//!
//! * the **order** of the systemd calls — network, then the two cert
//!   volumes, then `<name>-cage.service`. A cage started before its
//!   network unit is a quadlet whose static IP has no subnet.
//! * the **secret-store probe** that makes `Secret=` emission
//!   store-aware (issue #262), which happens *before* the render and
//!   whose failure has to degrade to "emit everything" rather than
//!   abort.
//! * that the metadata write lands **before** `start`, so
//!   `collect_used_octets` can read the real octet even if the start
//!   fails.

use std::collections::BTreeSet;

use agentcage_cli::backend::ContainerBackend;
use agentcage_cli::services::{self, DeployPlan};
use agentcage_core::config::{Config, FixedHost, load};
use agentcage_exec::{Elevation, FakeRunner, Reply};
use agentcage_state::{Paths, TestDir};

/// A minimal container cage, parsed the way `cage create` parses one.
fn config(name: &str) -> Config {
    let host = FixedHost {
        isolation: "container".to_owned(),
        dns_servers: Ok(vec!["192.0.2.53".to_owned()]),
    };
    load(
        "cage.yaml",
        &format!(
            "name: {name}\n\
             container:\n  \
               image: node:22-slim\n\
             domains:\n  \
               allow:\n    \
                 - example.com\n"
        ),
        &host,
    )
    .expect("the fixture parses")
}

/// `podman info`'s answer, reduced to the one key the renderer reads.
const PODMAN_INFO: &str = r#"{"host": {"security": {"rootless": true}}}"#;

/// Stub the calls a deploy makes, in the order it makes them.
fn stub_deploy(fake: &FakeRunner) {
    fake.assume_installed();
    // `build_artifacts`: one `podman build` of the egress image.
    fake.push(Reply::success());
    // `generate_units`: `podman info`, then the secret-store probe.
    fake.push(Reply::ok(PODMAN_INFO));
    fake.push(Reply::ok(""));
    // `install_units`: `systemctl --user daemon-reload`.
    fake.push(Reply::success());
    // `start`: three restarts and one start.
    fake.push_all([
        Reply::success(),
        Reply::success(),
        Reply::success(),
        Reply::success(),
    ]);
}

fn deploy(paths: &Paths, fake: &FakeRunner, config: &Config, network_octet: Option<u32>) {
    let backend = ContainerBackend::with_elevation(paths, fake, "9.9.9", Elevation::none());
    let used: BTreeSet<u32> = BTreeSet::new();
    services::build_and_deploy(
        &backend,
        paths,
        &DeployPlan {
            config,
            config_host_path: "/state/acme/cage.yaml",
            deploy_name: &config.name,
            used_octets: Some(&used),
            network_octet,
            quiet: true,
            no_cache: false,
            pull: false,
        },
    )
    .expect("the deploy succeeds against the stubs");
}

/// The whole sequence, exactly.
#[test]
fn the_deploy_sequence_is_the_pythons() {
    let dir = TestDir::new("deploy-argv");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    stub_deploy(&fake);

    deploy(&paths, &fake, &config("acme"), None);

    // The egress build. Its `-f` and context arguments are absolute
    // paths into the asset cache -- the one structural difference from
    // the Python (§2.1), where the package's own `data/` directory is
    // already on disk -- so they are checked by shape and the rest of
    // the line byte for byte.
    let build = fake.argv(0);
    let containerfile = build[5].clone();
    let context = build[build.len() - 1].clone();
    assert!(
        containerfile.ends_with("/containers/Containerfile.egress"),
        "containerfile: {containerfile}"
    );
    assert!(context.ends_with("/data"), "build context: {context}");
    fake.assert_call(
        0,
        &[
            "podman",
            "build",
            "-t",
            // Tagged with the running version, so the egress quadlet's
            // `Image=` pin matches what was just built.
            "agentcage-egress:9.9.9",
            "-f",
            &containerfile,
            // `setfcap` for dnsmasq's NET_BIND_SERVICE file capability;
            // the rest mirror the legacy proxy build.
            "--cap-add",
            "CAP_CHOWN",
            "--cap-add",
            "CAP_FOWNER",
            "--cap-add",
            "CAP_SETUID",
            "--cap-add",
            "CAP_SETGID",
            "--cap-add",
            "CAP_DAC_OVERRIDE",
            "--cap-add",
            "CAP_SETFCAP",
            &context,
        ],
    );

    // Everything after it, in order and with nothing extra.
    let rest: Vec<Vec<String>> = fake.argv_sequence().into_iter().skip(1).collect();
    let expected = [
        // `rootless=` comes from here, and it defaults to true when the
        // key is absent -- as the Python's chained `.get`s do.
        vec!["podman", "info", "--format", "json"],
        // The store-aware `Secret=` probe (issue #262), before the
        // render rather than after it.
        vec![
            "podman",
            "secret",
            "ls",
            "--noheading",
            "--format",
            "{{.Name}}",
        ],
        vec!["systemctl", "--user", "daemon-reload"],
        // Network first, then both cert volumes, then the cage. Any
        // other order starts a quadlet whose static IP has no subnet.
        vec!["systemctl", "--user", "restart", "acme-net-network.service"],
        vec![
            "systemctl",
            "--user",
            "restart",
            "acme-certs-volume.service",
        ],
        vec![
            "systemctl",
            "--user",
            "restart",
            "acme-public-certs-volume.service",
        ],
        vec!["systemctl", "--user", "start", "acme-cage.service"],
    ];
    assert_eq!(rest.len(), expected.len(), "{rest:#?}");
    for (actual, want) in rest.iter().zip(expected) {
        assert_eq!(actual.as_slice(), want.as_slice());
    }
    fake.assert_drained();
}

/// The metadata write happens before `start`, and records the octet the
/// renderer actually allocated.
#[test]
fn the_assigned_octet_is_persisted_before_the_cage_starts() {
    let dir = TestDir::new("deploy-octet");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    stub_deploy(&fake);

    // `cage update`'s shape: pin the subnet rather than re-deriving it.
    deploy(&paths, &fake, &config("acme"), Some(77));

    let metadata = paths.load_metadata("acme").expect("metadata was written");
    assert_eq!(
        metadata.get("network_octet"),
        Some(&agentcage_core::har::json::Json::Int(77)),
        "the pinned octet must be what is persisted, not the hash-derived one"
    );
    // And the units it rendered used it.
    let unit = std::fs::read_to_string(paths.quadlet_dir().join("acme-net.network"))
        .expect("the network unit was installed");
    assert!(unit.contains("10.89.77.0/24"), "{unit}");
}

/// A cage's five quadlet files land in the quadlet directory, not the
/// systemd user directory — §2.7's second trap, where a `.service` in
/// the quadlet dir fails silently at boot.
#[test]
fn every_unit_lands_in_the_directory_its_extension_calls_for() {
    let dir = TestDir::new("deploy-dirs");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    stub_deploy(&fake);

    deploy(&paths, &fake, &config("acme"), None);

    for unit in [
        "acme-net.network",
        "acme-certs.volume",
        "acme-public-certs.volume",
        "acme-egress.container",
        "acme-cage.container",
    ] {
        assert!(
            paths.quadlet_dir().join(unit).is_file(),
            "{unit} is not in the quadlet directory"
        );
    }
    assert!(
        std::fs::read_dir(paths.user_unit_dir())
            .expect("the user unit dir is created either way")
            .next()
            .is_none(),
        "a cage with no watcher should install no plain .service"
    );
}

/// The two `resolv.conf` files the quadlets bind-mount are written into
/// the shared patches directory before the render, because the render
/// bakes their paths into the units.
#[test]
fn the_resolv_files_are_written_before_the_units_that_mount_them() {
    let dir = TestDir::new("deploy-resolv");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    stub_deploy(&fake);

    deploy(&paths, &fake, &config("acme"), Some(5));

    let cage = paths.patches_dir().join("resolv-acme.conf");
    let egress = paths.patches_dir().join("resolv-egress-acme.conf");
    // The cage resolves through its own egress sidecar, whose dnsmasq
    // is allowlist-scoped...
    assert_eq!(
        std::fs::read_to_string(&cage).unwrap(),
        "nameserver 10.89.5.10\n"
    );
    // ...and the egress gets the configured upstreams and nothing else.
    assert_eq!(
        std::fs::read_to_string(&egress).unwrap(),
        "nameserver 192.0.2.53\n"
    );

    // The egress mount is `rw` on purpose: the supervisor prepends the
    // default-route gateway to this file at start, so what is seeded
    // here is the deterministic *fallback*. See `egress.container.j2`.
    let unit = std::fs::read_to_string(paths.quadlet_dir().join("acme-egress.container")).unwrap();
    assert!(
        unit.contains(&format!("{}:/etc/resolv.conf:rw", egress.display())),
        "the egress unit does not mount its seeded resolv.conf:\n{unit}"
    );
}

/// A secret-store probe that fails degrades to emit-everything rather
/// than failing the deploy.
///
/// Issue #262 cuts both ways: a store that *can* be queried drops a
/// `Secret=` whose entry is gone, and a store that cannot be queried at
/// all must keep the legacy behaviour. A deploy that aborted here would
/// make every podman hiccup a failed `cage update`.
#[test]
fn an_unqueryable_secret_store_does_not_fail_the_deploy() {
    let dir = TestDir::new("deploy-secrets");
    let paths = Paths::under(dir.path());
    let fake = FakeRunner::new();
    fake.assume_installed();
    fake.push(Reply::success());
    fake.push(Reply::ok(PODMAN_INFO));
    // `podman secret ls` fails.
    fake.push(Reply::failed(125, "cannot connect to podman"));
    fake.push_all([
        Reply::success(),
        Reply::success(),
        Reply::success(),
        Reply::success(),
        Reply::success(),
    ]);

    deploy(&paths, &fake, &config("acme"), None);
    fake.assert_drained();
}
