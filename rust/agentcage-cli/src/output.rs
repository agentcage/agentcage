//! Styled terminal output — the port of `src/agentcage/output.py`.
//!
//! Everything a user sees goes through here: the box-drawing banner, the
//! green tick, the red cross, the dim label column, the 44-column rule
//! and the braille spinner. It is eight helpers and a thread, and it is
//! the CLI's entire visible identity, so the port is held to the bytes
//! rather than to the idea — see `tests/fixtures/output/README.md`.
//!
//! # The colour rule, in full
//!
//! The Python builds every line with `click.style` and prints it with
//! `click.echo`, and the two do different jobs:
//!
//! * `click.style` **always** emits the SGR escapes. It looks at
//!   nothing.
//! * `click.echo` strips them again when the destination stream is not a
//!   terminal. With `color=None` and no `Context` setting `ctx.color`,
//!   `click._compat.should_strip_ansi` reduces to `not isatty(stream)`.
//!
//! agentcage never passes `color=` to `echo`, never sets `ctx.color`,
//! and reads neither `NO_COLOR` nor `FORCE_COLOR` — and neither does
//! click 8.4. `cage audit --no-color` is a per-command flag threaded
//! into [`agentcage_core::audit::format_table_row`]; it never reaches
//! this module. So the whole decision is: **is this particular stream a
//! terminal?**
//!
//! That shape is reproduced rather than flattened, because it has two
//! consequences a `color: bool` parameter would lose. The decision is
//! *per stream*, so `agentcage run > log` keeps the red cross (stderr)
//! and loses the green ticks (stdout). And because the escapes are added
//! first and removed later, **colour only ever adds escapes** — strip a
//! coloured line and you have the plain line, byte for byte. That is the
//! invariant PR C5 learned the hard way on the `cage audit` table, and
//! the fixture asserts it for every case here.
//!
//! Hence the split below: `*_text` functions build the styled string,
//! [`echo`] and [`echo_err`] decide what survives. A caller that needs
//! the string (the `--help` banner, PR D5) takes the first half; a
//! caller that prints takes the Python-named wrapper.
//!
//! # No colour crate
//!
//! Three constants and a strip function, and the strip function has to
//! match click's regex exactly. `anstream`/`owo-colors` would each bring
//! their own idea of when to colour — environment variables agentcage
//! does not read, a global override it does not have — and the job here
//! is byte-identical behaviour with the Python, not good colour policy.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

// ── the style primitives ─────────────────────────────────────

/// `click.style(text, dim=True)`.
#[must_use]
pub fn dim(text: &str) -> String {
    format!("\u{1b}[2m{text}\u{1b}[0m")
}

/// `click.style(text, fg="green")`.
#[must_use]
pub fn green(text: &str) -> String {
    format!("\u{1b}[32m{text}\u{1b}[0m")
}

/// `click.style(text, fg="red")`.
#[must_use]
pub fn red(text: &str) -> String {
    format!("\u{1b}[31m{text}\u{1b}[0m")
}

/// `click.style(text, bold=True)`, used only by the banner.
fn bold(text: &str) -> String {
    format!("\u{1b}[1m{text}\u{1b}[0m")
}

/// Remove ANSI escapes, exactly as `click.unstyle` does.
///
/// click's regex is `\033\[[;?0-9]*[a-zA-Z]` — a CSI introducer, any run
/// of digits, semicolons and question marks, then one ASCII letter.
/// Written out rather than pulled from a regex crate because the pattern
/// is four character classes and the crate would be the heaviest
/// dependency in the binary.
///
/// Note what it does *not* match: an escape that never reaches a letter
/// is left alone, escape sequences that are not CSI are left alone, and
/// a lone `\x1b` is left alone. Those cases do not arise from our own
/// styling, but a `msg` a user supplied can contain anything, and
/// matching click's blind spots is the point.
#[must_use]
pub fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < bytes.len() && matches!(bytes[j], b';' | b'?' | b'0'..=b'9') {
                j += 1;
            }
            if j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                i = j + 1;
                continue;
            }
        }
        // Not an escape: copy this character whole. Indexing by byte is
        // safe because `\x1b` and `[` are ASCII, so a match can never
        // start inside a multi-byte character.
        let len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + len]);
        i += len;
    }
    out
}

/// Byte length of the UTF-8 sequence starting with `first`.
fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// Pad on the right to `width` *characters*, like Python's `str.ljust`.
///
/// Characters, not bytes: `info("Größe", …)` pads to the same column as
/// `info("Grosse", …)`, and the banner's box closes at the same place
/// whatever the version string contains.
fn ljust(text: &str, width: usize) -> String {
    let len = text.chars().count();
    let mut out = String::with_capacity(text.len() + width.saturating_sub(len));
    out.push_str(text);
    for _ in len..width {
        out.push(' ');
    }
    out
}

// ── the lines ────────────────────────────────────────────────

/// The width floor of the banner box and the exact width of the rule.
///
/// The two are the same number in the Python and that is not a
/// coincidence, so they are the same constant here.
const RULE_WIDTH: usize = 44;

/// The `╭─╮` banner, styled, with a trailing blank line.
///
/// `width = max(len(title) + 2, 44)` where the title already carries a
/// space on each side. Below the floor the box is 44 wide and the
/// padding absorbs the difference; above it the box grows and the
/// padding stays at 2. A port that hard-codes 44 renders a ragged box
/// for any long version, which is what a `.dev` build has.
#[must_use]
pub fn banner_text(ver: &str) -> String {
    let title = format!(" \u{273b} agentcage v{ver} ");
    let title_len = title.chars().count();
    let width = (title_len + 2).max(RULE_WIDTH);
    let padding = width - title_len;
    let rule: String = "\u{2500}".repeat(width);
    format!(
        "{}\n{}{}{}{}\n{}\n",
        dim(&format!("\u{256d}{rule}\u{256e}")),
        dim("\u{2502}"),
        bold(&title),
        " ".repeat(padding),
        dim("\u{2502}"),
        dim(&format!("\u{2570}{rule}\u{256f}")),
    )
}

/// The green `✓` status line, styled.
#[must_use]
pub fn step_done_text(msg: &str) -> String {
    format!("  {} {msg}", green("\u{2713}"))
}

/// The red `✗` status line, styled.
#[must_use]
pub fn step_fail_text(msg: &str) -> String {
    format!("  {} {msg}", red("\u{2717}"))
}

/// A dim label + value info line, styled.
///
/// The label is padded to 9 *inside* the dim escapes, and `ljust` does
/// not truncate — a longer label runs straight into the value with no
/// separator at all. Both are load-bearing: the fixture records a case
/// of each.
#[must_use]
pub fn info_text(label: &str, value: &str) -> String {
    format!("  {}{value}", dim(&ljust(label, 9)))
}

/// The dim horizontal rule, styled.
#[must_use]
pub fn separator_text() -> String {
    dim(&"\u{2500}".repeat(RULE_WIDTH))
}

// ── printing ─────────────────────────────────────────────────

/// Write a line to stdout, stripping the escapes if it is not a terminal.
///
/// This is `click.echo(text)`: the newline is added here, and the colour
/// decision is made against *this* stream and nothing else.
pub fn echo(text: &str) {
    let mut out = std::io::stdout();
    let _ = if out.is_terminal() {
        writeln!(out, "{text}")
    } else {
        writeln!(out, "{}", strip_ansi(text))
    };
}

/// Write a line to stderr, stripping the escapes if it is not a terminal.
///
/// `click.echo(text, err=True)`. Separate from [`echo`] because the
/// decision is per stream: piping stdout does not decolour stderr.
pub fn echo_err(text: &str) {
    let mut err = std::io::stderr();
    let _ = if err.is_terminal() {
        writeln!(err, "{text}")
    } else {
        writeln!(err, "{}", strip_ansi(text))
    };
}

/// Write to stderr with no trailing newline (`click.echo(..., nl=False)`).
///
/// The spinner's only output shape: it rewrites one line rather than
/// printing lines, so it flushes by hand.
fn echo_err_no_newline(text: &str) {
    let mut err = std::io::stderr();
    let _ = if err.is_terminal() {
        write!(err, "{text}")
    } else {
        write!(err, "{}", strip_ansi(text))
    };
    let _ = err.flush();
}

/// Print the `╭─╮` banner with version.
pub fn banner(ver: &str) {
    echo(&banner_text(ver));
}

/// Print a green `✓` status line.
pub fn step_done(msg: &str) {
    echo(&step_done_text(msg));
}

/// Print a red `✗` status line **to stderr**.
pub fn step_fail(msg: &str) {
    echo_err(&step_fail_text(msg));
}

/// Print a dim label + value info line.
pub fn info(label: &str, value: &str) {
    echo(&info_text(label, value));
}

/// Print a dim horizontal rule.
pub fn separator() {
    echo(&separator_text());
}

// ── the spinner ──────────────────────────────────────────────

/// The braille frames, in order.
pub const SPINNER_FRAMES: &str =
    "\u{280b}\u{2819}\u{2839}\u{2838}\u{283c}\u{2834}\u{2826}\u{2827}\u{2807}\u{280f}";

/// How long each frame is held.
const FRAME_INTERVAL: Duration = Duration::from_millis(80);

/// Carriage return plus erase-to-end-of-line: how the spinner cleans up.
///
/// The only escape this module writes that is not a colour, which is why
/// the spinner is exempt from the "colour only adds escapes" invariant —
/// see the fixture README.
const CLEAR_LINE: &str = "\r\u{1b}[K";

/// The single line printed instead of animating when stderr is not a tty.
fn static_line(msg: &str) -> String {
    format!("  \u{2026} {msg}")
}

/// One frame of the animation, including the leading carriage return.
fn frame_line(frame: char, msg: &str) -> String {
    format!("\r  {frame} {msg}")
}

/// Where a spinner's bytes go: `(text, newline)`.
///
/// A closure rather than an enum with a test variant, so there is no
/// branch in the shipped binary that only the test suite can reach. The
/// real sink is `click.echo(..., err=True)`; the fixture test swaps in
/// one that appends to a `String`, because the animation is the one part
/// of this module that cannot be checked by calling a function and
/// comparing what it returns.
type Sink = Box<dyn Fn(&str, bool) + Send + Sync>;

/// The sink every non-test spinner uses.
fn stderr_sink() -> Sink {
    Box::new(|text: &str, newline: bool| {
        if newline {
            echo_err(text);
        } else {
            echo_err_no_newline(text);
        }
    })
}

/// The parts of a running spinner that `pause_active_spinner` reaches
/// through the module-level handle, behind interior mutability.
struct Inner {
    msg: String,
    /// Whether stderr was a terminal when the spinner started.
    ///
    /// Sampled once, like the Python samples `sys.stderr.isatty()` on
    /// every call — the answer cannot change mid-session, and sampling
    /// once means `pause`/`resume`/drop cannot disagree with `start`
    /// about whether a thread exists.
    tty: bool,
    sink: Sink,
    /// `None` for the real spinner; `Some(n)` stops each thread after
    /// `n` frames instead of sleeping, for the fixture test.
    frame_limit: Option<usize>,
    running: Mutex<Option<Running>>,
}

/// A live spin thread and the flag that stops it.
#[derive(Debug)]
struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("msg", &self.msg)
            .field("tty", &self.tty)
            .field("frame_limit", &self.frame_limit)
            .field("running", &self.running.lock().is_ok_and(|r| r.is_some()))
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn spawn(self: &Arc<Self>) {
        let stop = Arc::new(AtomicBool::new(false));
        let inner = Arc::clone(self);
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || inner.spin(&flag));
        *self.running.lock().expect("spinner state") = Some(Running { stop, thread });
    }

    /// The spin loop, `Spinner._spin` line for line.
    fn spin(&self, stop: &AtomicBool) {
        let mut drawn = 0usize;
        for frame in SPINNER_FRAMES.chars().cycle() {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            (self.sink)(&frame_line(frame, &self.msg), false);
            drawn += 1;
            match self.frame_limit {
                Some(limit) if drawn >= limit => break,
                Some(_) => {}
                None => std::thread::sleep(FRAME_INTERVAL),
            }
        }
    }

    /// Stop the thread if one is running, and wait for it.
    fn halt(&self) {
        let running = self.running.lock().expect("spinner state").take();
        if let Some(Running { stop, thread }) = running {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
        }
    }

    fn pause(&self) {
        if !self.tty {
            return;
        }
        self.halt();
        (self.sink)(CLEAR_LINE, false);
    }
}

/// Restarts the spinner it holds when dropped, including on an unwind.
struct Resume(Arc<Inner>);

impl Drop for Resume {
    fn drop(&mut self) {
        if self.0.tty {
            self.0.spawn();
        }
    }
}

/// The currently-active spinner, for [`pause_active_spinner`].
///
/// A `Weak`, not an `Arc`: the module-level handle must not keep a
/// spinner alive past its owner's scope. The Python's global has the
/// same intent — its `__exit__` clears `_active` only if it still points
/// at itself — and a `Weak` gets there without the check, because a
/// dropped spinner's handle simply stops upgrading.
static ACTIVE: OnceLock<Mutex<Weak<Inner>>> = OnceLock::new();

fn active() -> &'static Mutex<Weak<Inner>> {
    ACTIVE.get_or_init(|| Mutex::new(Weak::new()))
}

/// A braille spinner on the current line, for the length of a scope.
///
/// Falls back to a static `…` prefix when stderr is not a terminal — one
/// line, no thread, no animation, which is what CI logs contain.
///
/// Dropping it stops the thread and erases the line. That is the
/// `__exit__` of the Python context manager, and it runs on the panic
/// path too, which is the whole reason the release profile keeps
/// unwinding panics (see the root `Cargo.toml`).
#[derive(Debug)]
pub struct Spinner {
    inner: Arc<Inner>,
}

impl Spinner {
    /// Start spinning, with `msg` beside the frame.
    #[must_use]
    pub fn start(msg: &str) -> Self {
        Self::new(msg, std::io::stderr().is_terminal(), stderr_sink(), None)
    }

    fn new(msg: &str, tty: bool, sink: Sink, frame_limit: Option<usize>) -> Self {
        let inner = Arc::new(Inner {
            msg: msg.to_owned(),
            tty,
            sink,
            frame_limit,
            running: Mutex::new(None),
        });
        *active().lock().expect("active spinner") = Arc::downgrade(&inner);
        if inner.tty {
            inner.spawn();
        } else {
            (inner.sink)(&static_line(&inner.msg), true);
        }
        Self { inner }
    }

    /// Stop the spin thread and erase the line, keeping the message.
    ///
    /// No-op when stderr is not a terminal: the static line stays.
    pub fn pause(&self) {
        self.inner.pause();
    }

    /// Re-spawn the spin thread after a [`pause`](Self::pause).
    pub fn resume(&self) {
        if !self.inner.tty {
            return;
        }
        self.inner.spawn();
    }

    /// Wait for the current spin thread to stop on its own.
    ///
    /// Only ever returns for a frame-limited spinner, so this is a test
    /// seam and not a general one. It leaves the handle slot empty,
    /// which is what a later `pause` or `Drop` would have done with a
    /// thread that had already exited.
    #[cfg(test)]
    fn drain(&self) {
        let running = self.inner.running.lock().expect("spinner state").take();
        if let Some(Running { thread, .. }) = running {
            let _ = thread.join();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.inner.halt();
        if self.inner.tty {
            (self.inner.sink)(CLEAR_LINE, false);
        }
    }
}

/// Run `f` with the active spinner paused, if there is one.
///
/// Wrap the subprocess calls that stream their own progress to stderr —
/// Apple's `container` CLI does — so two writers do not fight over the
/// same line. A no-op when no spinner is running.
///
/// `f`'s panic is not caught: the spinner resumes on the way out because
/// the guard's `Drop` runs during the unwind, and then the panic
/// continues. Catching it here would swallow a failure the caller has to
/// see.
///
/// # Panics
///
/// If another thread panicked while holding the module-level handle to
/// the active spinner. That handle is held for a pointer copy, so a
/// poisoned lock means the process is already unwinding.
pub fn pause_active_spinner<T>(f: impl FnOnce() -> T) -> T {
    let Some(inner) = active().lock().expect("active spinner").upgrade() else {
        return f();
    };
    inner.pause();
    let _resume = Resume(Arc::clone(&inner));
    f()
}

#[cfg(test)]
mod tests {
    use super::{
        CLEAR_LINE, SPINNER_FRAMES, Sink, Spinner, banner_text, dim, frame_line, green, info_text,
        ljust, red, separator_text, static_line, step_done_text, step_fail_text, strip_ansi,
    };
    use std::sync::{Arc, Mutex};

    // ── the spinner, against tests/fixtures/output/spinner.json ──

    /// Drive a spinner into a capture buffer, exactly as the fixture
    /// generator drives the Python one: a fixed number of frames per
    /// thread instead of a timer, and every thread joined before the
    /// bytes are read.
    fn capture_sink(buf: &Arc<Mutex<String>>) -> Sink {
        let buf = Arc::clone(buf);
        Box::new(move |text: &str, newline: bool| {
            let mut buf = buf.lock().expect("capture sink");
            buf.push_str(text);
            if newline {
                buf.push('\n');
            }
        })
    }

    fn spin(msg: &str, frames: usize, tty: bool, pause: bool) -> String {
        let buf = Arc::new(Mutex::new(String::new()));
        {
            let spinner = Spinner::new(msg, tty, capture_sink(&buf), Some(frames));
            spinner.drain();
            if pause {
                spinner.pause();
                spinner.resume();
                spinner.drain();
            }
        }
        buf.lock().expect("capture").clone()
    }

    fn spinner_fixture() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/output/spinner.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("spinner.json"))
            .expect("spinner.json parses")
    }

    fn case(doc: &serde_json::Value, id: &str) -> serde_json::Value {
        doc["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no case {id}"))
            .clone()
    }

    #[test]
    fn frames_match_the_python() {
        let doc = spinner_fixture();
        assert_eq!(doc["frames"].as_str().expect("frames"), SPINNER_FRAMES);
        assert!((doc["frame_interval_seconds"].as_f64().expect("interval") - 0.08).abs() < 1e-9);
    }

    #[test]
    fn three_frames_on_a_tty() {
        let doc = spinner_fixture();
        let expected = case(&doc, "spinner-tty-three-frames");
        assert_eq!(
            spin("Starting cage...", 3, true, false),
            expected["color"]["err"].as_str().expect("err")
        );
        assert_eq!(
            spin("Starting cage...", 3, false, false),
            expected["plain"]["err"].as_str().expect("err")
        );
    }

    #[test]
    fn pause_and_resume_erase_and_restart() {
        let doc = spinner_fixture();
        let expected = case(&doc, "spinner-tty-pause-resume");
        assert_eq!(
            spin("Starting cage...", 2, true, true),
            expected["color"]["err"].as_str().expect("err")
        );
    }

    #[test]
    fn without_a_tty_it_prints_one_static_line() {
        let doc = spinner_fixture();
        let expected = case(&doc, "spinner-not-a-tty");
        assert_eq!(
            spin("Stopping cage...", 1, false, false),
            expected["color"]["err"].as_str().expect("err")
        );
    }

    /// The erase is the last thing a dropped spinner writes.
    ///
    /// This is the `Drop` the release profile's unwinding panics exist
    /// for: a spinner alive when a deploy blows up must not leave a
    /// braille frame stuck on the user's prompt.
    #[test]
    fn a_panic_still_erases_the_line() {
        let buf = Arc::new(Mutex::new(String::new()));
        let sink = capture_sink(&buf);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let spinner = Spinner::new("boom", true, sink, Some(1));
            spinner.drain();
            panic!("cage vanished");
        }));
        assert!(result.is_err());
        assert!(buf.lock().expect("capture").ends_with(CLEAR_LINE));
    }

    // ── the pure helpers ──
    //
    // The fixture is the real check (tests/golden_output.rs); these pin
    // the pieces that fixture cases are built out of, so a failure says
    // which piece moved.

    #[test]
    fn styles_wrap_with_a_reset() {
        assert_eq!(dim("x"), "\u{1b}[2mx\u{1b}[0m");
        assert_eq!(green("x"), "\u{1b}[32mx\u{1b}[0m");
        assert_eq!(red("x"), "\u{1b}[31mx\u{1b}[0m");
        // Nesting keeps both resets; the inner one is not the outer one.
        assert_eq!(dim(&green("x")), "\u{1b}[2m\u{1b}[32mx\u{1b}[0m\u{1b}[0m");
    }

    #[test]
    fn strip_ansi_matches_clicks_regex() {
        assert_eq!(strip_ansi(&dim("x")), "x");
        assert_eq!(strip_ansi(&step_done_text("ok")), "  \u{2713} ok");
        assert_eq!(strip_ansi("\u{1b}[?25h\u{1b}[0m."), ".");
        // click's regex needs the terminating letter; without one the
        // escape is left in place, and so is a bare ESC.
        assert_eq!(strip_ansi("\u{1b}[38;5;"), "\u{1b}[38;5;");
        assert_eq!(strip_ansi("\u{1b}"), "\u{1b}");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}"), "\u{1b}]0;title\u{7}");
        // Multi-byte characters survive the byte-wise scan.
        assert_eq!(strip_ansi(&dim("caf\u{e9} \u{2713}")), "caf\u{e9} \u{2713}");
    }

    #[test]
    fn ljust_counts_characters_not_bytes() {
        assert_eq!(ljust("Name", 9), "Name     ");
        assert_eq!(ljust("Endpoints", 9), "Endpoints");
        assert_eq!(
            ljust("Provisioned", 9),
            "Provisioned",
            "ljust never truncates"
        );
        assert_eq!(ljust("Gr\u{f6}\u{df}e", 9).chars().count(), 9);
    }

    #[test]
    fn the_banner_box_closes_where_the_rule_ends() {
        for ver in ["0.0.0", "0.40.1", &"a".repeat(40)] {
            let plain = strip_ansi(&banner_text(ver));
            let lines: Vec<&str> = plain.split('\n').collect();
            assert_eq!(lines.len(), 4, "three lines and a blank one");
            assert_eq!(lines[3], "");
            let widths: Vec<usize> = lines[..3].iter().map(|l| l.chars().count()).collect();
            assert_eq!(widths[0], widths[1], "{ver}");
            assert_eq!(widths[1], widths[2], "{ver}");
            assert!(widths[0] >= 46, "the 44-column floor plus two corners");
        }
    }

    #[test]
    fn the_rule_and_the_banner_floor_are_the_same_width() {
        assert_eq!(strip_ansi(&separator_text()).chars().count(), 44);
        assert_eq!(
            strip_ansi(&banner_text("0.0.0"))
                .lines()
                .next()
                .expect("top")
                .chars()
                .count(),
            46
        );
    }

    #[test]
    fn the_status_lines_are_two_spaces_a_mark_and_a_space() {
        assert_eq!(strip_ansi(&step_fail_text("boom")), "  \u{2717} boom");
        assert_eq!(strip_ansi(&info_text("Name", "web")), "  Name     web");
        assert_eq!(static_line("hi"), "  \u{2026} hi");
        assert_eq!(frame_line('\u{280b}', "hi"), "\r  \u{280b} hi");
    }
}
