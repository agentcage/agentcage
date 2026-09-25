//! Race the atomic writer, because a single-threaded test of an
//! atomicity primitive proves nothing.
//!
//! `_atomic_write_text` exists for one reason: `cage.yaml`,
//! `metadata.json` and `grants.yaml` are written by the host CLI and,
//! for the last one, by the in-container egress addon, while a third
//! process — the grants reconcile, `domain list`, a concurrent
//! `cage update` — is reading them. A reader that catches a truncated
//! prefix dies on a `YAMLError` or a `JSONDecodeError` and aborts the
//! reconcile.
//!
//! So the tests here are not "does it write the bytes". They are:
//!
//! | test | property |
//! | :-- | :-- |
//! | [`racing_threads_never_tear_a_read`] | with real concurrent writers and real concurrent readers, **every** read is a whole document |
//! | [`a_naive_writer_tears_under_the_same_race`] | the control — the same harness against `fs::write` *does* tear, so the test above is measuring something |
//! | [`racing_processes_never_tear_a_read`] | the same, across real `fork`+`exec` processes rather than threads |
//! | [`writers_sharing_one_pid_never_unlink_each_others_temps`] | the cross-PID-namespace case: every writer picks the same base temp name, and the loser aborts rather than deleting a file it does not own |
//! | [`the_target_never_disappears`] | `rename(2)` publishes; the target is never unlinked, so a reader never sees "no such file" once it exists |
//!
//! # The payload is large on purpose
//!
//! Each writer writes a few hundred kilobytes. A `write(2)` that size
//! is not atomic — the kernel will happily let a reader see a prefix —
//! which is exactly what makes the control test tear reliably and what
//! would make a naive port of this function fail here rather than in
//! production six months later.
//!
//! # The same-PID case is the interesting one
//!
//! Threads share a PID, so every thread in
//! [`writers_sharing_one_pid_never_unlink_each_others_temps`] picks the
//! *same* `<p>.<pid>.tmp` base name. That is precisely the collision
//! the Python's comment is about — "because PID namespaces share a
//! numeric space, a *different* writer's in-flight temp at the same
//! numeric PID" — and it is unreachable by forking, since fork gives
//! distinct PIDs. A thread race reproduces it for free.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use agentcage_state::{StateError, TestDir, atomic_write_text_as};

/// How big each writer's document is.
///
/// Big enough that a non-atomic write is observably non-atomic.
const PAYLOAD_BYTES: usize = 400 * 1024;

/// One writer's document: a distinctive header, a body of one repeated
/// character, and the same header again as a terminator.
///
/// Any prefix, any suffix and any mixture of two writers' bytes fails
/// [`classify`] — which is what "torn" means here. A payload of
/// identical bytes would make a torn read indistinguishable from a
/// whole one.
fn payload(id: usize) -> String {
    let mark = format!("<<{id:04}>>");
    let filler = char::from(b'a' + u8::try_from(id % 26).unwrap());
    let body: String = std::iter::repeat_n(filler, PAYLOAD_BYTES).collect();
    format!("{mark}{body}{mark}")
}

/// Which writer's document this is, or `None` if it is not any of them.
fn classify(text: &str, writers: usize) -> Option<usize> {
    (0..writers).find(|&id| text == payload(id))
}

// ─────────────────────────────────────────────────────────
// the race harness
// ─────────────────────────────────────────────────────────

/// What one race produced.
#[derive(Debug, Default)]
struct Outcome {
    /// Reads that matched some writer's document exactly.
    whole: u64,
    /// Reads that matched nothing — a torn read.
    torn: u64,
    /// Reads that found no file at all.
    absent: u64,
    /// Writers that returned `Ok`.
    wrote: u64,
    /// Writers that aborted on a temp-name collision.
    collided: u64,
}

/// Run `writers` threads writing `rounds` documents each to one path,
/// against `readers` threads reading it as fast as they can.
///
/// `write` is the writer under test, so the same harness measures the
/// atomic writer and the naive one.
fn race(
    target: &Path,
    writers: usize,
    readers: usize,
    rounds: usize,
    writer: fn(&Path, &str, usize) -> Result<(), StateError>,
) -> Outcome {
    let target = Arc::new(target.to_path_buf());
    let gate = Arc::new(Barrier::new(writers + readers));
    let done = Arc::new(AtomicBool::new(false));
    let (whole, torn, absent) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let (wrote, collided) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));

    let mut handles = Vec::new();
    for id in 0..writers {
        let (target, gate) = (Arc::clone(&target), Arc::clone(&gate));
        let (wrote, collided) = (Arc::clone(&wrote), Arc::clone(&collided));
        handles.push(thread::spawn(move || {
            let text = payload(id);
            gate.wait();
            for _ in 0..rounds {
                match writer(&target, &text, id) {
                    Ok(()) => wrote.fetch_add(1, Ordering::Relaxed),
                    Err(StateError::TempCollision { .. }) => {
                        collided.fetch_add(1, Ordering::Relaxed)
                    }
                    Err(error) => panic!("writer {id}: {error}"),
                };
            }
        }));
    }
    for _ in 0..readers {
        let (target, gate, done) = (Arc::clone(&target), Arc::clone(&gate), Arc::clone(&done));
        let (whole, torn, absent) = (Arc::clone(&whole), Arc::clone(&torn), Arc::clone(&absent));
        handles.push(thread::spawn(move || {
            gate.wait();
            while !done.load(Ordering::Relaxed) {
                match fs::read_to_string(&*target) {
                    Ok(text) if classify(&text, writers).is_some() => {
                        whole.fetch_add(1, Ordering::Relaxed)
                    }
                    Ok(_) => torn.fetch_add(1, Ordering::Relaxed),
                    Err(_) => absent.fetch_add(1, Ordering::Relaxed),
                };
            }
        }));
    }

    // The writers finish first; then the readers are told to stop.
    let readers_start = handles.len() - readers;
    for handle in handles.drain(..readers_start) {
        handle.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    for handle in handles {
        handle.join().unwrap();
    }

    Outcome {
        whole: whole.load(Ordering::Relaxed),
        torn: torn.load(Ordering::Relaxed),
        absent: absent.load(Ordering::Relaxed),
        wrote: wrote.load(Ordering::Relaxed),
        collided: collided.load(Ordering::Relaxed),
    }
}

/// The writer under test, with a per-thread PID so no two writers pick
/// the same temp name.
///
/// This is the realistic shape: the host CLI and the in-container
/// addon are different processes, and normally have different numeric
/// PIDs. The pathological same-PID case has its own test.
fn atomic_distinct_pids(path: &Path, text: &str, id: usize) -> Result<(), StateError> {
    atomic_write_text_as(path, text, 9000 + u32::try_from(id).unwrap())
}

/// The naive writer this function exists to replace.
///
/// Its `Result` is always `Ok`; it is there so that the same `race`
/// harness measures both writers, which is the whole point of the
/// control.
#[expect(
    clippy::unnecessary_wraps,
    reason = "shares the signature of the writer under test"
)]
fn naive(path: &Path, text: &str, _id: usize) -> Result<(), StateError> {
    fs::write(path, text).unwrap();
    Ok(())
}

// ─────────────────────────────────────────────────────────
// the tests
// ─────────────────────────────────────────────────────────

#[test]
fn racing_threads_never_tear_a_read() {
    let dir = TestDir::new("atomic-race");
    let target = dir.join("cage.yaml");
    let outcome = race(&target, 6, 3, 40, atomic_distinct_pids);

    assert_eq!(
        outcome.torn, 0,
        "a reader saw a partial document: {outcome:?}"
    );
    assert_eq!(outcome.collided, 0, "distinct PIDs must not collide");
    assert_eq!(outcome.wrote, 6 * 40);
    assert!(
        outcome.whole > 0,
        "the readers never managed a read: {outcome:?}"
    );

    // The file settled on exactly one writer's document, whole.
    let final_text = fs::read_to_string(&target).unwrap();
    assert!(classify(&final_text, 6).is_some());
    assert_no_temps_left(dir.path());
}

#[test]
fn a_naive_writer_tears_under_the_same_race() {
    // The control. Without it, `racing_threads_never_tear_a_read`
    // could be passing because the race never happens rather than
    // because the writer is atomic -- and a test that cannot
    // distinguish those two is not testing the thing it names.
    //
    // A `write(2)` of 400 KiB is not atomic: the reader sees whatever
    // has landed so far. Whether a given reader thread gets scheduled
    // inside one is up to the kernel, so this retries rather than
    // betting the suite on one roll -- but across 25 attempts a
    // `fs::write` that never tears would mean the harness has stopped
    // racing, and the test above has stopped meaning anything.
    const ATTEMPTS: usize = 25;

    let mut total = Outcome::default();
    for _ in 0..ATTEMPTS {
        let dir = TestDir::new("atomic-race-control");
        let outcome = race(&dir.join("cage.yaml"), 6, 3, 40, naive);
        total.torn += outcome.torn;
        total.whole += outcome.whole;
        if total.torn > 0 {
            break;
        }
    }

    assert!(
        total.torn > 0,
        "{ATTEMPTS} races and `fs::write` never tore once: {total:?}"
    );
}

#[test]
fn the_target_never_disappears() {
    // `rename(2)` replaces the target in one step and never unlinks
    // it, so a reader that opened the path once can keep reading it.
    // A writer built from unlink-then-create would show up here.
    let dir = TestDir::new("atomic-race-absent");
    let target = dir.join("grants.yaml");
    atomic_write_text_as(&target, &payload(0), 1).unwrap();

    let outcome = race(&target, 4, 3, 40, atomic_distinct_pids);
    assert_eq!(
        outcome.absent, 0,
        "the target vanished mid-race: {outcome:?}"
    );
    assert_eq!(outcome.torn, 0);
}

#[test]
fn writers_sharing_one_pid_never_unlink_each_others_temps() {
    // Threads share a PID, so all the writers here pick the *same*
    // `<p>.<pid>.tmp` base name. That is the cross-PID-namespace
    // collision the Python's comment is about, and it is unreachable
    // by forking, which hands out distinct PIDs.
    //
    // The base name is *also* pre-planted, standing in for the
    // in-container addon's in-flight temp at the same numeric PID, so
    // every writer is pushed onto the single counter-suffixed retry
    // and they contend for that one name.
    //
    // Two things must hold. The safety properties are checked on every
    // attempt:
    //
    //   * no reader ever sees a torn document -- an aborted write
    //     publishes nothing;
    //   * the planted temp is never unlinked. Deleting it is the
    //     tempting "clean up the stale temp and retry", and it is a
    //     lost write: that file may be another writer's in-flight
    //     document, whose rename would then fail.
    //
    // And the collision itself has to actually happen, or the first
    // property is vacuous. Whether six threads overlap inside one
    // ~400 KiB write is up to the scheduler and it does sometimes
    // serialise, so the race is retried until a collision is seen
    // rather than asserted on one roll of the dice.
    const PLANTED: &str = "ANOTHER NAMESPACE'S IN-FLIGHT TEMP";
    const ATTEMPTS: usize = 25;

    fn same_pid(path: &Path, text: &str, _id: usize) -> Result<(), StateError> {
        atomic_write_text_as(path, text, 4242)
    }

    let mut total = Outcome::default();
    for attempt in 0..ATTEMPTS {
        let dir = TestDir::new("atomic-race-samepid");
        let target = dir.join("cage.yaml");
        let planted = dir.join("cage.yaml.4242.tmp");
        fs::write(&planted, PLANTED).unwrap();

        let outcome = race(&target, 6, 3, 60, same_pid);

        assert_eq!(
            outcome.torn, 0,
            "attempt {attempt}: a reader saw a partial document: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(&planted).unwrap(),
            PLANTED,
            "attempt {attempt}: another writer's in-flight temp was clobbered"
        );
        assert!(
            outcome.wrote > 0,
            "attempt {attempt}: nothing was ever published: {outcome:?}"
        );
        assert_eq!(outcome.wrote + outcome.collided, 6 * 60);
        assert!(classify(&fs::read_to_string(&target).unwrap(), 6).is_some());
        // The planted temp is the only one left; every success renamed
        // its own away and every abort created none.
        assert_eq!(
            temps_in(dir.path()),
            vec![planted.clone()],
            "attempt {attempt}: unexpected leftovers"
        );

        total.wrote += outcome.wrote;
        total.collided += outcome.collided;
        total.torn += outcome.torn;
        if outcome.collided > 0 {
            break;
        }
    }

    assert!(
        total.collided > 0,
        "{ATTEMPTS} races of six threads on one PID never collided -- \
         the harness has stopped racing: {total:?}"
    );
}

#[test]
fn racing_processes_never_tear_a_read() {
    // Threads share an address space and a PID; separate processes
    // share neither, which is the shape the host CLI and the egress
    // addon actually have. Each child gets a real distinct PID from
    // the kernel, so the temp names differ for the reason the Python
    // relies on rather than because a test passed a number in.
    //
    // The children rendezvous on a `go` file before writing and stop
    // on a `stop` file, rather than each writing a fixed number of
    // documents: process startup here is a whole test binary, and a
    // child that finishes before the next one has started is not a
    // race. With the rendezvous the overlap is structural, which is
    // why `seen.len() > 1` below can be an assertion.
    let dir = TestDir::new("atomic-race-procs");
    let target = dir.join("metadata.json");
    let workers = 5;

    let mut children: Vec<std::process::Child> = (0..workers)
        .map(|id| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD_TEST, "--nocapture"])
                .env(CHILD_PATH, &target)
                .env(CHILD_ID, id.to_string())
                .env(CHILD_SIGNALS, dir.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn the child writer")
        })
        .collect();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while (0..workers).any(|id| !dir.join(format!("ready-{id}")).exists()) {
        assert!(
            std::time::Instant::now() < deadline,
            "a child never started"
        );
        thread::yield_now();
    }
    fs::write(dir.join("go"), "").unwrap();

    let mut whole = 0u64;
    let mut torn = 0u64;
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let read_until = std::time::Instant::now() + std::time::Duration::from_millis(750);
    while std::time::Instant::now() < read_until || seen.len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "never saw two writers: {seen:?}, {whole} whole reads"
        );
        // Before the first publish there is no file at all; after it
        // there always is (see `the_target_never_disappears`).
        if let Ok(text) = fs::read_to_string(&target) {
            match classify(&text, workers) {
                Some(id) => {
                    whole += 1;
                    seen.insert(id);
                }
                None => torn += 1,
            }
        }
    }
    fs::write(dir.join("stop"), "").unwrap();
    for mut child in children.drain(..) {
        assert!(child.wait().unwrap().success(), "a child writer failed");
    }

    assert_eq!(
        torn, 0,
        "a reader saw a partial document ({whole} whole reads)"
    );
    assert!(whole > 0, "the parent never read the file");
    assert!(
        seen.len() > 1,
        "only writer {seen:?} was ever observed -- the processes did not overlap"
    );
    assert!(classify(&fs::read_to_string(&target).unwrap(), workers).is_some());
    assert_no_temps_left(dir.path());
}

/// No `.tmp` survived.
///
/// A successful write renames its temp away; an aborted one removes
/// its own or never created it; and a *collision* leaves the other
/// writer's temp for that writer to rename. Once every writer has
/// finished, none of those can still be on disk.
fn assert_no_temps_left(dir: &Path) {
    let leftovers = temps_in(dir);
    assert!(leftovers.is_empty(), "temp files survived: {leftovers:?}");
}

/// Every `.tmp` in `dir`, sorted.
fn temps_in(dir: &Path) -> Vec<PathBuf> {
    let mut temps: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_string_lossy().ends_with(".tmp"))
        .collect();
    temps.sort();
    temps
}

// ─────────────────────────────────────────────────────────
// the child half of the multi-process test
// ─────────────────────────────────────────────────────────

const CHILD_TEST: &str = "the_child_writer";
const CHILD_PATH: &str = "AGENTCAGE_ATOMIC_CHILD_PATH";
const CHILD_ID: &str = "AGENTCAGE_ATOMIC_CHILD_ID";
const CHILD_SIGNALS: &str = "AGENTCAGE_ATOMIC_CHILD_SIGNALS";

/// One process's share of [`racing_processes_never_tear_a_read`].
///
/// A `#[test]` rather than a separate binary so that `cargo test`
/// builds it without a second target and the parent can re-exec itself
/// with `--exact`. In an ordinary run the environment is unset and
/// this returns immediately, which is why it asserts nothing on its
/// own -- the parent does the asserting.
#[test]
fn the_child_writer() {
    let Ok(path) = std::env::var(CHILD_PATH) else {
        return;
    };
    let id: usize = std::env::var(CHILD_ID).unwrap().parse().unwrap();
    let signals = PathBuf::from(std::env::var(CHILD_SIGNALS).unwrap());
    let text = payload(id);
    let path = PathBuf::from(path);

    fs::write(signals.join(format!("ready-{id}")), "").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !signals.join("go").exists() {
        assert!(std::time::Instant::now() < deadline, "no go signal");
        thread::yield_now();
    }
    while !signals.join("stop").exists() {
        assert!(std::time::Instant::now() < deadline, "no stop signal");
        // The real entry point, so the PID really does come from
        // `getpid()` rather than from a test parameter.
        agentcage_state::atomic_write_text(&path, &text).unwrap();
    }
}
