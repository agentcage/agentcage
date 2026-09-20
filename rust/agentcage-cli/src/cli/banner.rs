//! The `╭─╮` banner that `_BannerGroup` prints above the root help.
//!
//! # Why this is not in `output`
//!
//! It belongs there, and `output.banner_text` is exactly where the
//! Python keeps it. PR D4 is porting `output`/`terminal`/`_timing` in a
//! branch beside this one, and both branches need the banner: D5 to put
//! it above `agentcage --help`, D4 to golden-test it. Writing it twice
//! in one file each is a smaller mess than two branches editing the same
//! new module, and the duplication is *checked* — `cli_surface.rs`
//! asserts this output against the click fixture, so when D4's
//! `output::banner_text` lands, deleting this module and calling that
//! one cannot silently change the help screen.
//!
//! # The width is not arbitrary
//!
//! `output.py:22` is `width = max(len(title) + 2, 44)`, and the title is
//! `" ✻ agentcage v{ver} "`. For every version string shorter than 20
//! characters the 44 wins, which is why the box does not grow when the
//! patch number does. Reproduce the formula rather than the 44, or the
//! first long pre-release tag prints a broken box.

/// ANSI SGR 2 / 0, as `click.style(dim=True)` emits them.
const DIM: &str = "\u{1b}[2m";
/// ANSI SGR 1 / 0, as `click.style(bold=True)` emits them.
const BOLD: &str = "\u{1b}[1m";
/// The reset click appends to every styled span.
const RESET: &str = "\u{1b}[0m";

/// The banner, with a trailing blank line, as `banner_text` returns it.
///
/// `styled` is `false` whenever the destination is not a terminal.
/// `click.echo` strips styles from a non-tty stream, so the Python
/// prints a plain box into a pipe; matching that is what lets the
/// generated fixture be compared against this at all.
pub(crate) fn banner_text(version: &str, styled: bool) -> String {
    let title = format!(" \u{273b} agentcage v{version} ");
    // `str::chars().count()`, not `len()`: `✻` is three bytes and one
    // column, and Python measured columns.
    let title_width = title.chars().count();
    let width = std::cmp::max(title_width + 2, 44);
    let padding = " ".repeat(width - title_width);
    let rule = "\u{2500}".repeat(width);

    let (dim_open, bold_open, reset) = if styled {
        (DIM, BOLD, RESET)
    } else {
        ("", "", "")
    };

    format!(
        "{dim_open}\u{256d}{rule}\u{256e}{reset}\n\
         {dim_open}\u{2502}{reset}{bold_open}{title}{reset}{padding}{dim_open}\u{2502}{reset}\n\
         {dim_open}\u{2570}{rule}\u{256f}{reset}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::banner_text;

    /// The exact bytes `output.banner_text('0.40.1')` returns, styled.
    #[test]
    fn styled_banner_matches_click_style_output() {
        let expected = concat!(
            "\u{1b}[2m╭────────────────────────────────────────────╮\u{1b}[0m\n",
            "\u{1b}[2m│\u{1b}[0m\u{1b}[1m ✻ agentcage v0.40.1 \u{1b}[0m",
            "                       \u{1b}[2m│\u{1b}[0m\n",
            "\u{1b}[2m╰────────────────────────────────────────────╯\u{1b}[0m\n",
        );
        assert_eq!(banner_text("0.40.1", true), expected);
    }

    /// A long version grows the box rather than overflowing it.
    #[test]
    fn a_long_version_widens_the_box() {
        // The `max(.., 44)` floor absorbs anything up to a 27-character
        // version, so a merely long one proves nothing; this is past it.
        let text = banner_text("1.0.0-rc.1+build.2026091900001", false);
        let widths: Vec<usize> = text.lines().map(|l| l.chars().count()).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{widths:?}");
        assert_eq!(widths[0], 49, "{widths:?}");
    }

    /// Unstyled output carries no escape bytes at all.
    #[test]
    fn unstyled_banner_has_no_ansi() {
        assert!(!banner_text("0.40.1", false).contains('\u{1b}'));
    }
}
