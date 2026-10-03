//! `init.py` — the scaffold search path, the config renderer, and
//! `run_scaffold_setup`.
//!
//! # Where the built-in scaffolds live
//!
//! In Python they are package data: `Path(__file__).parent /
//! "scaffolds"`. Here they are embedded in the binary by
//! `agentcage-assets` and extracted, byte- and mode-identical, into a
//! digest-keyed cache directory. [`Scaffolds::system`] resolves that
//! once and then everything below is ordinary path work — which matters,
//! because a scaffold is not just a template: `run_scaffold_setup`
//! builds a *podman build context* out of the directory, and a
//! Containerfile that `COPY`s `entrypoint.sh` needs the file to exist on
//! disk with its executable bit intact.
//!
//! The other three search roots are the Python's, unchanged: a
//! project-local `.agentcage/scaffolds` under the git root, a user
//! `~/.config/agentcage/scaffolds`, and the legacy
//! `templates/presets/<name>.yaml.j2` single-file form.
//!
//! # `python3` in a scaffold Containerfile
//!
//! Several scaffolds `apt-get install python3`. That is the *workload's*
//! runtime, not agentcage's, and it is explicitly outside the port's
//! no-Python invariant: the invariant is about what the host binary
//! needs in order to run, and a caged agent's image may contain whatever
//! the agent needs.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentcage_core::config::types::OrderedMap;
use agentcage_exec::{Command, CommandRunner, Sink};

/// `init._SCAFFOLD_NAME_RE` — `^[a-z0-9][a-z0-9-]{0,62}$`.
///
/// Spelled out rather than compiled, because it is also the guard that
/// keeps a scaffold name from being a path: `..` and `a/b` both fail it,
/// which is the only thing standing between `--scaffold` and an
/// arbitrary read.
#[must_use]
pub fn valid_scaffold_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    name.len() <= 63 && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Where a scaffold was found, as `scaffold list` and `scaffold show`
/// label it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `<git-root>/.agentcage/scaffolds/<name>`.
    Local,
    /// `~/.config/agentcage/scaffolds/<name>`.
    User,
    /// Shipped with agentcage.
    Builtin,
}

impl Source {
    /// The label `scaffold_source` returns.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::User => "user",
            Self::Builtin => "built-in",
        }
    }
}

/// The four roots `init.py` searches, resolved once.
///
/// The Python recomputes `_project_scaffolds_dir()` on every call, which
/// means a `git rev-parse` per lookup — `list_scaffolds()` alone does
/// one, and `scaffold_aliases()` does one more per scaffold. The working
/// directory does not move inside a single command, so this resolves it
/// once and hands the same answer out.
#[derive(Clone, Debug)]
pub struct Scaffolds {
    project: Option<PathBuf>,
    user: PathBuf,
    builtin: PathBuf,
    templates: PathBuf,
}

impl Scaffolds {
    /// The real search path: git root, `XDG_CONFIG_HOME`, and the
    /// extracted asset trees.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the embedded assets cannot be extracted, which
    /// is the one failure that makes every scaffold unreachable.
    pub fn system(runner: &dyn CommandRunner) -> io::Result<Self> {
        let root = agentcage_assets::extract::ensure_extracted()?;
        Ok(Self {
            project: project_scaffolds_dir(runner),
            user: user_scaffolds_dir(),
            builtin: root.join("scaffolds"),
            templates: root.join("templates"),
        })
    }

    /// A search path with explicit roots, for tests.
    #[must_use]
    pub fn from_roots(
        project: Option<PathBuf>,
        user: PathBuf,
        builtin: PathBuf,
        templates: PathBuf,
    ) -> Self {
        Self {
            project,
            user,
            builtin,
            templates,
        }
    }

    /// `~/.config/agentcage/scaffolds` — where `scaffold create` writes.
    #[must_use]
    pub fn user_dir(&self) -> &Path {
        &self.user
    }

    /// The extracted `templates/` tree.
    #[must_use]
    pub fn templates_dir(&self) -> &Path {
        &self.templates
    }

    /// `init.resolve_scaffold` — the first root that holds the name.
    ///
    /// The legacy preset case is the Python's oddity and is reproduced
    /// as-is: a `templates/presets/<name>.yaml.j2` resolves to the
    /// *presets directory*, not to a per-scaffold one, and every caller
    /// then has to cope with `<dir>/cage.yaml.j2` not existing.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<PathBuf> {
        if !valid_scaffold_name(name) {
            return None;
        }
        if let Some(project) = &self.project {
            let candidate = project.join(name);
            if candidate.join("cage.yaml.j2").exists() {
                return Some(candidate);
            }
        }
        let candidate = self.user.join(name);
        if candidate.join("cage.yaml.j2").exists() {
            return Some(candidate);
        }
        let candidate = self.builtin.join(name);
        if candidate.join("cage.yaml.j2").exists() {
            return Some(candidate);
        }
        let preset = self
            .templates
            .join("presets")
            .join(format!("{name}.yaml.j2"));
        if preset.exists() {
            return preset.parent().map(Path::to_path_buf);
        }
        None
    }

    /// `init.is_builtin_scaffold`.
    #[must_use]
    pub fn is_builtin(&self, name: &str) -> bool {
        self.builtin.join(name).join("cage.yaml.j2").exists()
    }

    /// `init.scaffold_source`.
    ///
    /// Note what it does *not* do: it never checks that the scaffold
    /// exists at all. A name with no directory anywhere reads as
    /// `built-in`, exactly as the Python's final `return "built-in"`
    /// does, and every caller has already resolved the scaffold first.
    #[must_use]
    pub fn source(&self, name: &str) -> Source {
        if let Some(project) = &self.project {
            if project.join(name).join("cage.yaml.j2").exists() {
                return Source::Local;
            }
        }
        if self.user.join(name).join("cage.yaml.j2").exists() {
            return Source::User;
        }
        Source::Builtin
    }

    /// `init.list_scaffolds` — every name, sorted, deduplicated.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let preset_dir = self.templates.join("presets");
        if let Ok(entries) = fs::read_dir(&preset_dir) {
            for entry in entries.flatten() {
                let file = entry.file_name();
                let file = file.to_string_lossy();
                // `p.stem.removesuffix(".yaml")` over a `*.yaml.j2` glob.
                if let Some(stem) = file.strip_suffix(".yaml.j2") {
                    names.insert(stem.to_owned());
                }
            }
        }
        for dir in self.search_dirs() {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.path().join("cage.yaml.j2").exists() {
                    names.insert(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        names.into_iter().collect()
    }

    /// `init._scaffold_search_dirs` — the directory roots, in order.
    fn search_dirs(&self) -> Vec<&Path> {
        let mut dirs: Vec<&Path> = Vec::new();
        if let Some(project) = self.project.as_deref() {
            if project.is_dir() {
                dirs.push(project);
            }
        }
        if self.user.is_dir() {
            dirs.push(&self.user);
        }
        if self.builtin.is_dir() {
            dirs.push(&self.builtin);
        }
        dirs
    }

    /// `init.load_scaffold_meta` — the scaffold's `scaffold.yaml`.
    ///
    /// `None` means "no scaffold, or no `scaffold.yaml`"; an empty file
    /// is `Some(default)`, which is what `yaml.safe_load(f) or {}`
    /// produces and what `run_scaffold_setup`'s `if meta is None`
    /// distinguishes.
    #[must_use]
    pub fn meta(&self, name: &str) -> Option<Meta> {
        let dir = self.resolve(name)?;
        let file = dir.join("scaffold.yaml");
        if !file.exists() {
            return None;
        }
        let text = fs::read_to_string(&file).ok()?;
        match agentcage_core::yaml::from_str::<Option<Meta>>(&text) {
            Ok(meta) => Some(meta.unwrap_or_default()),
            Err(error) => {
                eprintln!("warning: {}: {error}", file.display());
                Some(Meta::default())
            }
        }
    }

    /// `init.scaffold_aliases` — `alias → scaffold`, from every
    /// scaffold's own `scaffold.yaml`.
    ///
    /// agentcage core has no hard-coded knowledge of which scaffolds
    /// exist or how they prefer to be invoked, which is why this is a
    /// scan rather than a table.
    #[must_use]
    pub fn aliases(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for name in self.list() {
            let Some(meta) = self.meta(&name) else {
                continue;
            };
            for alias in meta.aliases {
                out.insert(alias, name.clone());
            }
        }
        out
    }

    /// `init.scaffold_name_prefix` — the cage-name prefix, defaulting to
    /// the scaffold's own name.
    #[must_use]
    pub fn name_prefix(&self, name: &str) -> String {
        self.meta(name)
            .and_then(|meta| meta.name_prefix)
            .filter(|prefix| !prefix.is_empty())
            .unwrap_or_else(|| name.to_owned())
    }
}

/// `init._USER_SCAFFOLDS_DIR`.
fn user_scaffolds_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(
            || {
                std::env::var_os("HOME").map_or_else(
                    || PathBuf::from("~/.config"),
                    |home| PathBuf::from(home).join(".config"),
                )
            },
            PathBuf::from,
        );
    base.join("agentcage").join("scaffolds")
}

/// `init._project_scaffolds_dir` — `<git-root>/.agentcage/scaffolds`.
///
/// `None` outside a git repository, and `None` when `git` is not
/// installed. The Python's five-second timeout is kept: a `git rev-parse`
/// against a hung network filesystem must not wedge `agentcage run`.
fn project_scaffolds_dir(runner: &dyn CommandRunner) -> Option<PathBuf> {
    let command = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .stdout(Sink::Capture)
        .stderr(Sink::Capture)
        .timeout(Duration::from_secs(5));
    let output = runner.run(&command).ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root).join(".agentcage").join("scaffolds"))
}

// ── scaffold.yaml ────────────────────────────────────────────

/// A scaffold's `scaffold.yaml`.
///
/// Every field is optional because every field is optional in the
/// Python, which reaches for them with `meta.get(...)`. Unknown keys are
/// ignored rather than rejected: a scaffold written against a newer
/// agentcage should still render on an older one.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Meta {
    /// One-line summary, shown by `scaffold list` and `scaffold show`.
    pub description: String,
    /// `service` or `session` — the cage's lifecycle.
    pub lifecycle: String,
    /// Alternative names `agentcage run` accepts for this scaffold.
    pub aliases: Vec<String>,
    /// Prefix for auto-generated cage names.
    pub name_prefix: Option<String>,
    /// Images to build before the cage is created.
    pub build: Vec<Build>,
    /// Files to drop on the host, if they are not there already.
    pub provision: Vec<Provision>,
    /// What to tell the operator after `init` wrote the config.
    pub next_steps: Vec<String>,
}

/// One entry of `build:`.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Build {
    /// The image tag to produce.
    pub image: String,
    /// Build from this Containerfile, relative to the scaffold dir.
    pub containerfile: Option<String>,
    /// Build from a shallow clone of this repository instead.
    pub git: Option<String>,
    /// `--depth` for the clone.
    pub depth: Option<i64>,
    /// `--cap-add` for the build.
    pub cap_add: Vec<String>,
    /// `--build-arg`s, in declaration order.
    pub build_args: OrderedMap<String>,
}

/// One entry of `provision:`.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Provision {
    /// Source, relative to the scaffold directory.
    pub src: String,
    /// Destination on the host; `~` is expanded.
    pub dest: String,
}

// ── rendering ────────────────────────────────────────────────

/// A render failed.
#[derive(Debug)]
pub enum RenderError {
    /// `click.ClickException(f"scaffold {scaffold!r} not found")`.
    NotFound(String),
    /// The template could not be read.
    Io(String),
    /// The template is malformed, or rendering it raised.
    Template(String),
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(name) => write!(f, "scaffold '{name}' not found"),
            Self::Io(message) | Self::Template(message) => f.write_str(message),
        }
    }
}

/// What `render_config` renders.
#[derive(Clone, Debug)]
pub struct RenderRequest<'a> {
    /// The cage name — `{{ name }}`.
    pub name: &'a str,
    /// `{{ image }}`, used only by the blank starter template.
    pub image: &'a str,
    /// `{{ isolation }}`.
    pub isolation: &'a str,
    /// The scaffold to render, or `None` for the blank starter.
    pub scaffold: Option<&'a str>,
    /// `{{ port }}` — `None` renders as Jinja's `none`.
    pub port: Option<i64>,
}

/// `init.render_config`.
///
/// Two shapes, and they take different context: the blank starter gets
/// `name`, `image`, `isolation` and `port`; a scaffold gets `name`,
/// `isolation`, `port` and the cage's three derived network addresses,
/// and never sees `image`. That asymmetry is the Python's and is
/// load-bearing — a scaffold pins its own image.
///
/// # Errors
///
/// [`RenderError`] when the scaffold is unknown, its template cannot be
/// read, or rendering it fails.
pub fn render_config(
    scaffolds: &Scaffolds,
    request: &RenderRequest<'_>,
) -> Result<String, RenderError> {
    render_config_with(scaffolds, request, agentcage_state::mint_placeholder)
}

/// [`render_config`] with the `placeholder()` generator supplied.
///
/// The generator is a parameter for the same reason `agentcage-core`
/// takes one: minting a token is a read from the OS entropy pool, and
/// the render-diff test against the Python's own fixtures needs the
/// counter the fixture generator pins.
///
/// # Errors
///
/// As [`render_config`].
pub fn render_config_with(
    scaffolds: &Scaffolds,
    request: &RenderRequest<'_>,
    generator: impl Fn(&str) -> String + Send + Sync + 'static,
) -> Result<String, RenderError> {
    let Some(scaffold) = request.scaffold else {
        return render_template(
            "init-config.yaml.j2",
            &read_embedded("templates/init-config.yaml.j2")?,
            &StarterContext {
                name: request.name,
                image: request.image,
                isolation: request.isolation,
                port: request.port,
            },
            generator,
        );
    };

    let Some(dir) = scaffolds.resolve(scaffold) else {
        return Err(RenderError::NotFound(scaffold.to_owned()));
    };

    let file = dir.join("cage.yaml.j2");
    let (template_name, source) = if file.exists() {
        let text = fs::read_to_string(&file)
            .map_err(|error| RenderError::Io(format!("{}: {error}", file.display())))?;
        ("cage.yaml.j2".to_owned(), text)
    } else {
        // The legacy single-file preset. `resolve` handed back the
        // presets directory, so the file is named after the scaffold.
        let preset = dir.join(format!("{scaffold}.yaml.j2"));
        let text = fs::read_to_string(&preset)
            .map_err(|error| RenderError::Io(format!("{}: {error}", preset.display())))?;
        (format!("presets/{scaffold}.yaml.j2"), text)
    };

    // A user or project scaffold that shadows one agentcage ships is
    // legitimate and deliberate — but silently is not how it should
    // happen.
    let source_label = scaffolds.source(scaffold);
    if source_label != Source::Builtin && scaffolds.is_builtin(scaffold) {
        eprintln!(
            "note: using {} scaffold '{scaffold}' (shadows built-in)",
            source_label.label()
        );
    }

    let addrs = agentcage_core::quadlets::cage_network_addrs(request.name, None, None)
        .map_err(|error| RenderError::Template(error.to_string()))?;
    render_template(
        &template_name,
        &source,
        &ScaffoldContext {
            name: request.name,
            isolation: request.isolation,
            port: request.port,
            subnet: &addrs.subnet,
            ip_cage: &addrs.ip_cage,
            ip_egress: &addrs.ip_egress,
        },
        generator,
    )
}

/// The blank starter's context — `init-config.yaml.j2` is the one
/// template that sees `image`.
#[derive(Debug, serde::Serialize)]
struct StarterContext<'a> {
    name: &'a str,
    image: &'a str,
    isolation: &'a str,
    port: Option<i64>,
}

/// A scaffold's context.
///
/// No `image`: a scaffold pins its own, and the three network addresses
/// are there because a scaffold may need to name the cage's own subnet
/// (the `pi` scaffold's relay listeners do).
#[derive(Debug, serde::Serialize)]
struct ScaffoldContext<'a> {
    name: &'a str,
    isolation: &'a str,
    port: Option<i64>,
    subnet: &'a str,
    ip_cage: &'a str,
    ip_egress: &'a str,
}

/// The one embedded template the blank starter path needs.
fn read_embedded(path: &str) -> Result<String, RenderError> {
    agentcage_assets::embedded_files()
        .iter()
        .find(|file| file.path == path)
        .and_then(|file| std::str::from_utf8(file.bytes).ok())
        .map(str::to_owned)
        .ok_or_else(|| RenderError::Io(format!("{path} is missing from the embedded assets")))
}

/// Render one source against the shared environment plus a live
/// `placeholder()`.
///
/// In production the generator is `agentcage_state::mint_placeholder`,
/// so a rendered config carries a concrete 128-bit token and the
/// operator never has to fill one in — the same reason `init.py`
/// installs `config.generate_placeholder` here.
fn render_template<S: serde::Serialize>(
    name: &str,
    source: &str,
    context: &S,
    generator: impl Fn(&str) -> String + Send + Sync + 'static,
) -> Result<String, RenderError> {
    agentcage_core::quadlets::templates::render_source(name, source, context, generator)
        .map_err(|error| RenderError::Template(format!("{name}: {error}")))
}

// ── run_scaffold_setup ───────────────────────────────────────

/// Everything `run_scaffold_setup` needs beyond the scaffold itself.
#[derive(Clone, Copy, Debug)]
pub struct SetupOptions<'a> {
    /// `None` preserves the Python's legacy behaviour (run the host
    /// build loop); `Some("container")` does the same explicitly, and
    /// `vm` / `apple-container` skip it because those backends build
    /// their own images.
    pub isolation: Option<&'a str>,
    /// Capture the build output instead of streaming it.
    pub quiet: bool,
    /// `podman build --no-cache`, and bypass the "already exists" skip.
    pub no_cache: bool,
    /// `podman build --pull=always`, and bypass the "already exists" skip.
    pub pull: bool,
}

/// `init.run_scaffold_setup` — build the scaffold's images, drop its
/// provisioned files.
///
/// # Errors
///
/// A message ready for `output.step_fail`, when a build or a clone
/// fails. A provisioning copy that fails is reported and does not abort,
/// matching the Python only in that the Python would raise — see the
/// inline note.
pub fn run_scaffold_setup(
    scaffolds: &Scaffolds,
    runner: &dyn CommandRunner,
    name: &str,
    options: &SetupOptions<'_>,
) -> Result<(), String> {
    let Some(meta) = scaffolds.meta(name) else {
        return Ok(());
    };
    let Some(dir) = scaffolds.resolve(name) else {
        return Ok(());
    };

    let echo = |message: &str| {
        if !options.quiet {
            crate::output::echo(message);
        }
    };

    let host_builds = matches!(options.isolation, None | Some("container"));
    if host_builds {
        let podman = agentcage_exec::tools::podman::Podman::new(runner);
        for entry in &meta.build {
            build_one(
                scaffolds, runner, &podman, &dir, name, entry, options, &echo,
            )?;
        }
    } else if !meta.build.is_empty() {
        echo(&format!(
            "Skipping host image build for {} isolation; images will be built by the backend at cage create.",
            options.isolation.unwrap_or_default()
        ));
    }

    let host = crate::hostenv::RealQuadletHost::new(std::path::PathBuf::new());
    for entry in &meta.provision {
        let src = dir.join(&entry.src);
        let dest = agentcage_core::quadlets::expanduser(&entry.dest, &host);
        let dest = Path::new(&dest);
        if dest.exists() {
            echo(&format!("{} already exists, skipping.", dest.display()));
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        fs::copy(&src, dest).map_err(|error| format!("{}: {error}", src.display()))?;
        echo(&format!("Created {}", dest.display()));
    }
    Ok(())
}

/// One `build:` entry.
#[expect(
    clippy::too_many_arguments,
    reason = "the loop body of `run_scaffold_setup`, lifted out so the \
              `containerfile:` and `git:` branches are readable. Every \
              argument is something the caller already holds."
)]
fn build_one(
    scaffolds: &Scaffolds,
    runner: &dyn CommandRunner,
    podman: &agentcage_exec::tools::podman::Podman<'_>,
    dir: &Path,
    scaffold: &str,
    entry: &Build,
    options: &SetupOptions<'_>,
    echo: &dyn Fn(&str),
) -> Result<(), String> {
    let image = &entry.image;
    let forced = options.no_cache || options.pull;
    if !forced && podman.image_exists(image).unwrap_or(false) {
        echo(&format!("Image {image} already exists, skipping build."));
        return Ok(());
    }

    // Scaffold-declared build args resolve against the scaffold's own
    // declaration: a pinned value is honoured verbatim, an untagged one
    // is re-resolved against the registry at build time.
    let (build_args, changes) =
        crate::registry::resolve_scaffold_build_args(runner, &entry.build_args);
    for change in &changes {
        echo(&format!("Build arg {}: {}", change.key, change.new));
    }

    let build = |containerfile: Option<String>, context: &Path| -> Result<(), String> {
        podman
            .build_image(
                image,
                &context.display().to_string(),
                &agentcage_exec::tools::podman::BuildOptions {
                    containerfile,
                    cap_add: entry.cap_add.clone(),
                    no_cache: options.no_cache,
                    pull: options.pull,
                    build_args: build_args.clone(),
                    quiet: options.quiet,
                },
            )
            .map_err(|error| error.to_string())
    };

    if let Some(containerfile) = &entry.containerfile {
        echo(&format!("Building {image}..."));
        // Build from a *staged copy* of the scaffold directory, not from
        // the directory itself: the canonical `AGENTS.md` brief and the
        // `agentcage` skill are deliberately not shipped per-scaffold,
        // so `COPY AGENTS.md` only resolves once they have been dropped
        // into the context. Mirrors the deployment-dir staging in
        // `cage create` and in the ephemeral `run` flow.
        let staging = TempDir::new("agentcage-scaffold-")
            .map_err(|error| format!("could not stage the build context: {error}"))?;
        copy_tree(dir, staging.path())
            .map_err(|error| format!("could not stage the build context: {error}"))?;
        let staged_containerfile = staging.path().join(containerfile);
        let _ =
            crate::staging::stage_scaffold_assets(&staged_containerfile, staging.path(), scaffold);
        build(
            Some(staged_containerfile.display().to_string()),
            staging.path(),
        )
    } else if let Some(url) = &entry.git {
        let depth = entry.depth.unwrap_or(1);
        let clone = TempDir::new("agentcage-clone-")
            .map_err(|error| format!("could not create a clone directory: {error}"))?;
        echo(&format!("Cloning {url}..."));
        let mut command = Command::new("git").args([
            "clone".to_owned(),
            format!("--depth={depth}"),
            url.clone(),
            clone.path().display().to_string(),
        ]);
        if options.quiet {
            command = command.stdout(Sink::Capture).stderr(Sink::Capture);
        }
        runner
            .run(&command)
            .map_err(|error| error.to_string())?
            .check("git")
            .map_err(|error| error.to_string())?;
        echo(&format!("Building {image}..."));
        build(None, clone.path())
    } else {
        // Neither `containerfile:` nor `git:` — nothing to build, which
        // is what the Python's `if/elif` with no `else` does.
        let _ = scaffolds;
        Ok(())
    }
}

/// `shutil.copytree(src, dst, dirs_exist_ok=True)` — no ignore list.
///
/// Deliberately unfiltered, unlike [`crate::staging::stage_build_context`]:
/// this is the scaffold's *own* directory going into a temporary build
/// context, and a scaffold that ships a `node_modules/` its Containerfile
/// `COPY`s would break if it were pruned.
fn copy_tree(source: &Path, dest: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
            // `shutil.copy2` carries the mode, and an `entrypoint.sh`
            // that arrives non-executable fails the image at runtime
            // rather than at build time.
            let mode = fs::metadata(&from)?.permissions().mode();
            fs::set_permissions(&to, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// `tempfile.TemporaryDirectory()` — created on construction, removed on
/// drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// A fresh directory under `$TMPDIR` whose name starts with
    /// `prefix`.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the directory cannot be created.
    pub fn new(prefix: &str) -> io::Result<Self> {
        let base = std::env::var_os("TMPDIR").map_or_else(
            || PathBuf::from("/tmp"),
            |value| {
                if value.is_empty() {
                    PathBuf::from("/tmp")
                } else {
                    PathBuf::from(value)
                }
            },
        );
        for attempt in 0..64u32 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path = base.join(format!(
                "{prefix}{}-{nanos:x}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    // 0o700: a build context can hold a scaffold's own
                    // files, and `$TMPDIR` is usually world-traversable.
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("could not create a temporary directory"))
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RenderRequest, Scaffolds, Source, render_config, render_config_with, valid_scaffold_name,
    };
    use std::path::PathBuf;

    /// The embedded search path, with no project or user roots — what a
    /// test wants, and what CI has.
    fn builtin_only() -> Scaffolds {
        let root = agentcage_assets::extract::ensure_extracted().expect("assets extract");
        Scaffolds::from_roots(
            None,
            PathBuf::from("/nonexistent/agentcage-user-scaffolds"),
            root.join("scaffolds"),
            root.join("templates"),
        )
    }

    #[test]
    fn names_that_could_be_paths_are_refused() {
        assert!(valid_scaffold_name("openclaw"));
        assert!(valid_scaffold_name("my-claude-2"));
        assert!(valid_scaffold_name("9"));
        assert!(!valid_scaffold_name(""));
        assert!(!valid_scaffold_name("-lead"));
        assert!(!valid_scaffold_name(".."));
        assert!(!valid_scaffold_name("a/b"));
        assert!(!valid_scaffold_name("Upper"));
        assert!(!valid_scaffold_name(&"a".repeat(64)));
        assert!(valid_scaffold_name(&"a".repeat(63)));
    }

    /// The scaffolds this binary ships, against the manifest the Python
    /// generator writes. One more or one fewer is a real change; a name
    /// going missing is a packaging bug.
    #[test]
    fn every_shipped_scaffold_is_listed() {
        let manifest = std::fs::read_to_string(
            repo_root().join("tests/fixtures/scaffold-configs/MANIFEST.txt"),
        )
        .expect("MANIFEST.txt");
        let expected: Vec<String> = manifest.lines().map(str::to_owned).collect();
        assert_eq!(builtin_only().list(), expected);
    }

    #[test]
    fn a_shipped_scaffold_resolves_to_its_extracted_directory() {
        let scaffolds = builtin_only();
        let dir = scaffolds.resolve("openclaw").expect("openclaw resolves");
        assert!(dir.join("cage.yaml.j2").is_file());
        assert!(dir.join("Containerfile").is_file());
        assert_eq!(scaffolds.source("openclaw"), Source::Builtin);
        assert!(scaffolds.is_builtin("openclaw"));
        assert!(scaffolds.resolve("../../etc").is_none());
    }

    /// The scaffold's `entrypoint.sh` must arrive executable, or the
    /// image builds and then fails to start.
    #[test]
    fn extracted_scaffold_scripts_keep_their_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let scaffolds = builtin_only();
        let dir = scaffolds.resolve("openclaw").expect("openclaw resolves");
        let mode = std::fs::metadata(dir.join("entrypoint.sh"))
            .expect("entrypoint.sh")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "mode {mode:o}");
    }

    #[test]
    fn scaffold_metadata_is_read_from_the_scaffold_dir() {
        let scaffolds = builtin_only();
        let meta = scaffolds.meta("openclaw").expect("openclaw has metadata");
        assert_eq!(meta.lifecycle, "service");
        assert_eq!(meta.build.len(), 1);
        assert_eq!(
            meta.build[0].containerfile.as_deref(),
            Some("Containerfile")
        );
        assert_eq!(
            meta.build[0]
                .build_args
                .get("BASE_IMAGE")
                .map(String::as_str),
            Some("ghcr.io/openclaw/openclaw")
        );
        assert!(!meta.next_steps.is_empty());
        assert_eq!(scaffolds.name_prefix("openclaw"), "openclaw");
    }

    /// **The render diff.** Every scaffold, rendered by this code, is
    /// byte-identical to what the Python renderer produced into
    /// `tests/fixtures/scaffold-configs/<name>/cage.yaml`.
    ///
    /// The fixtures are generated by `scripts/gen-scaffold-configs.py`,
    /// which pins `secrets.token_hex` to a per-scaffold counter so the
    /// entropic placeholders are reproducible; the same counter is used
    /// here. Everything else — whitespace, key order, the
    /// `default(18789, true)` fallback, the derived network addresses —
    /// is the renderer's own output.
    #[test]
    fn every_scaffold_renders_byte_identically_to_the_python() {
        let scaffolds = builtin_only();
        let names = scaffolds.list();
        assert!(!names.is_empty(), "no scaffolds found");
        for name in names {
            let expected = std::fs::read_to_string(
                repo_root().join(format!("tests/fixtures/scaffold-configs/{name}/cage.yaml")),
            )
            .unwrap_or_else(|error| panic!("{name}: fixture: {error}"));
            let rendered = render_config_with(
                &scaffolds,
                &RenderRequest {
                    // `gen-scaffold-configs.py`'s CAGE_NAME.
                    name: "demo",
                    image: "node:22-slim",
                    isolation: "container",
                    scaffold: Some(&name),
                    port: None,
                },
                counting_placeholder(),
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(rendered, expected, "{name} renders differently");
        }
    }

    /// `gen-scaffold-configs.py`'s pinned `secrets.token_hex`: a counter
    /// zero-padded to 32 hex characters, restarted per render.
    fn counting_placeholder() -> impl Fn(&str) -> String + Send + Sync + 'static {
        let counter = std::sync::atomic::AtomicU32::new(0);
        move |env: &str| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            agentcage_core::config::placeholder::placeholder_for(env, &format!("{n:032x}"))
        }
    }

    /// The repository root, four levels up from this crate's source.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("rust/<crate> has a grandparent")
            .to_path_buf()
    }

    /// `port | default(18789, true)` — Jinja2's three-argument
    /// `default`, which minijinja's two-argument builtin cannot express.
    /// With no `--port`, openclaw must still pin 18789.
    #[test]
    fn the_openclaw_default_port_survives_a_none_port() {
        let scaffolds = builtin_only();
        let text = render_config(
            &scaffolds,
            &RenderRequest {
                name: "oc",
                image: "",
                isolation: "container",
                scaffold: Some("openclaw"),
                port: None,
            },
        )
        .expect("openclaw renders");
        assert!(text.contains("18789"), "{text}");
        assert!(!text.contains("none"), "{text}");

        let pinned = render_config(
            &scaffolds,
            &RenderRequest {
                name: "oc",
                image: "",
                isolation: "container",
                scaffold: Some("openclaw"),
                port: Some(19999),
            },
        )
        .expect("openclaw renders");
        assert!(pinned.contains("19999"), "{pinned}");
    }

    /// Each render mints fresh entropy — two cages must not share a
    /// placeholder token.
    #[test]
    fn placeholders_are_entropic_and_unique_per_render() {
        let scaffolds = builtin_only();
        let render = || {
            render_config(
                &scaffolds,
                &RenderRequest {
                    name: "oc",
                    image: "",
                    isolation: "container",
                    scaffold: Some("openclaw"),
                    port: None,
                },
            )
            .expect("renders")
        };
        let first = render();
        let second = render();
        assert!(
            first.contains("agentcage:secret:ANTHROPIC_API_KEY:"),
            "{first}"
        );
        assert_ne!(first, second);
    }

    #[test]
    fn the_blank_starter_renders_without_a_scaffold() {
        let scaffolds = builtin_only();
        let text = render_config(
            &scaffolds,
            &RenderRequest {
                name: "blank",
                image: "node:22-slim",
                isolation: "container",
                scaffold: None,
                port: None,
            },
        )
        .expect("starter renders");
        assert!(text.contains("name: blank"), "{text}");
        assert!(text.contains("node:22-slim"), "{text}");
    }

    #[test]
    fn an_unknown_scaffold_is_reported_by_name() {
        let scaffolds = builtin_only();
        let error = render_config(
            &scaffolds,
            &RenderRequest {
                name: "x",
                image: "",
                isolation: "container",
                scaffold: Some("nope"),
                port: None,
            },
        )
        .expect_err("unknown scaffold");
        assert_eq!(error.to_string(), "scaffold 'nope' not found");
    }
}
