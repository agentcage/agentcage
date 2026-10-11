//! Helpers shared by the audit and capture tests: an in-memory stderr,
//! scratch directories, and the corpus file plumbing (paths, bless mode,
//! field accessors).

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentcage_core::har::datetime::DateTime;

use crate::json::{self, DumpOptions, Json};

/// A `Write` that keeps everything, shareable with the writer.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedBuf(pub(crate) Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub(crate) fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A fresh directory under the system temp dir, removed on drop.
#[derive(Debug)]
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agentcage-egress-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn corpus_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/egress")
        .join(name)
}

pub(crate) fn blessing() -> bool {
    std::env::var_os("AGENTCAGE_BLESS").is_some_and(|v| v == "1")
}

/// Rewrite a corpus document exactly as the generators write it
/// (`json.dumps(doc, indent=2)` plus a newline).
pub(crate) fn write_corpus(name: &str, doc: &Json) {
    let mut text = json::dumps(doc, DumpOptions::indented());
    text.push('\n');
    std::fs::write(corpus_path(name), text).unwrap();
}

pub(crate) fn s<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string {key}"))
}

pub(crate) fn int(v: &Json, key: &str) -> i64 {
    match v.get(key) {
        Some(Json::Int(i)) => *i,
        other => panic!("{key} is not an int: {other:?}"),
    }
}

pub(crate) fn arr<'a>(v: &'a Json, key: &str) -> &'a [Json] {
    match v.get(key) {
        Some(Json::Array(items)) => items,
        other => panic!("{key} is not an array: {other:?}"),
    }
}

pub(crate) fn date(parts: &[Json]) -> DateTime {
    let n: Vec<i64> = parts
        .iter()
        .map(|p| match p {
            Json::Int(i) => *i,
            _ => panic!("bad date part"),
        })
        .collect();
    let u = |i: usize| u32::try_from(n[i]).unwrap();
    DateTime::from_parts((n[0], u(1), u(2)), (u(3), u(4), u(5), u(6)), Some(0)).unwrap()
}
