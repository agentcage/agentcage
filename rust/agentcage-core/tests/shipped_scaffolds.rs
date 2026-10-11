//! Checks on the scaffolds agentcage ships under `src/agentcage/scaffolds/`.
//!
//! Three layers: the canonical sandbox brief and Agent Skill every agent
//! scaffold bakes in (and the `Containerfile` lines that do it), each
//! scaffold's `scaffold.yaml` metadata, and the rendered `cage.yaml`.
//!
//! The rendered checks read `tests/fixtures/scaffold-configs/<name>/cage.yaml`
//! instead of rendering `cage.yaml.j2` here. Those fixtures are what the
//! shipped templates render to for a cage named `demo`, and
//! `agentcage-cli`'s `every_scaffold_renders_byte_identically_to_its_fixture`
//! pins the renderer to them byte for byte, so asserting on a fixture is
//! asserting on the template's output. These semantic checks are what keep
//! a hand-edited fixture honest.

mod common;

use agentcage_core::yaml::{self, Value};

use common::repo_root;

fn scaffolds_dir() -> std::path::PathBuf {
    repo_root().join("src/agentcage/scaffolds")
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn containerfile(scaffold: &str) -> String {
    read(&scaffolds_dir().join(scaffold).join("Containerfile"))
}

/// Byte offset of `needle`, or a panic naming it.
fn index_of(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not found"))
}

/// scaffold -> (agent memory file the brief is copied to, home dir chowned to node)
const BRIEF_WIRING: [(&str, &str, &str); 3] = [
    (
        "claude-code",
        "/home/node/.claude/CLAUDE.md",
        "/home/node/.claude",
    ),
    ("codex", "/home/node/.codex/AGENTS.md", "/home/node/.codex"),
    ("pi", "/home/node/.pi/agent/AGENTS.md", "/home/node/.pi"),
];

/// scaffold -> (skills dir the skill is copied to, dir chowned to node)
const SKILL_WIRING: [(&str, &str, &str); 3] = [
    (
        "claude-code",
        "/home/node/.claude/skills/agentcage",
        "/home/node/.claude",
    ),
    (
        "codex",
        "/home/node/.codex/skills/agentcage",
        "/home/node/.codex",
    ),
    (
        "pi",
        "/home/node/.agents/skills/agentcage",
        "/home/node/.agents",
    ),
];

// ── scaffolds/AGENTS.md: the sandbox brief ───────────────────────────────

/// One canonical brief, staged into each build context at build time,
/// never duplicated into a scaffold directory.
#[test]
fn single_canonical_brief_and_no_per_scaffold_copies() {
    assert!(scaffolds_dir().join("AGENTS.md").is_file());
    for (name, _, _) in BRIEF_WIRING {
        assert!(
            !scaffolds_dir().join(name).join("AGENTS.md").exists(),
            "{name} carries its own copy of the brief"
        );
    }
}

#[test]
fn canonical_brief_content() {
    let brief = read(&scaffolds_dir().join("AGENTS.md"));
    assert!(brief.starts_with("# You are running inside agentcage"));
    let low = brief.to_lowercase();
    for needle in ["proxy", "placeholder", "agentcage_version"] {
        assert!(low.contains(needle), "{needle}");
    }
    // Short: it lands in the agent's context window.
    assert!(brief.lines().count() < 60);
}

/// Plain `COPY` into the agent's own memory file, before `USER node`,
/// with the home dir chowned back to node so the file stays writable and
/// the agent's own state writes still work. A real file, not a shell
/// redirect or `@import` indirection.
#[test]
fn containerfiles_copy_the_brief_into_agent_memory_writable() {
    for (scaffold, mem_path, home_dir) in BRIEF_WIRING {
        let cf = containerfile(scaffold);
        assert!(
            cf.contains(&format!("COPY AGENTS.md {mem_path}")),
            "{scaffold}"
        );
        assert!(
            cf.contains(&format!("chown -R node:node {home_dir}")),
            "{scaffold}"
        );
        assert!(
            index_of(&cf, "COPY AGENTS.md") < index_of(&cf, "USER node"),
            "{scaffold}"
        );
        assert!(!cf.contains(&format!("> {mem_path}")), "{scaffold}");
    }
}

// ── scaffolds/skills/agentcage: the Agent Skill ──────────────────────────

#[test]
fn single_canonical_skill_and_no_per_scaffold_copies() {
    assert!(scaffolds_dir().join("skills/agentcage/SKILL.md").is_file());
    for (name, _, _) in SKILL_WIRING {
        assert!(
            !scaffolds_dir().join(name).join("skills").exists(),
            "{name} carries its own skills dir"
        );
    }
}

/// Agent Skills standard: YAML frontmatter with `name` (== directory
/// name) and a non-empty description, plus the endpoints the skill exists
/// to teach.
#[test]
fn canonical_skill_frontmatter_and_content() {
    let text = read(&scaffolds_dir().join("skills/agentcage/SKILL.md"));
    assert!(text.starts_with("---\n"));
    let frontmatter = text.split("---\n").nth(1).expect("frontmatter");
    assert!(frontmatter.contains("name: agentcage\n"));
    let desc = frontmatter
        .lines()
        .find(|l| l.starts_with("description:"))
        .expect("a description");
    let prefix = "description: ".len();
    assert!(desc.len() > prefix + 40, "{desc}");
    assert!(desc.len() <= prefix + 1024, "description too long");
    let body = text.to_lowercase();
    for needle in [
        "/v1/health",
        "get",
        "/v1/allowlist",
        "post",
        "/v1/allowlist/requests",
        "/v1/allowlist/removals",
        "agentcage.local",
        "reason",
        "403",
        "placeholder",
    ] {
        assert!(body.contains(needle), "{needle}");
    }
}

/// Copied into each agent's skills dir, owned by node afterwards, before
/// `USER node` like the brief.
#[test]
fn containerfiles_copy_the_skill_into_agent_skills_dir() {
    for (scaffold, skill_path, home_dir) in SKILL_WIRING {
        let cf = containerfile(scaffold);
        let copy_line = format!("COPY skills/agentcage {skill_path}");
        let copy = index_of(&cf, &copy_line);
        assert!(
            copy < index_of(&cf, &format!("chown -R node:node {home_dir}")),
            "{scaffold}"
        );
        assert!(copy < index_of(&cf, "USER node"), "{scaffold}");
    }
}

// ── scaffolds/<name>/scaffold.yaml ───────────────────────────────────────

fn meta(scaffold: &str) -> Value {
    let path = scaffolds_dir().join(scaffold).join("scaffold.yaml");
    yaml::load(&read(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn the_shipped_scaffolds_include_the_agent_and_service_ones() {
    let names: Vec<String> = std::fs::read_dir(scaffolds_dir())
        .expect("scaffolds/")
        .filter_map(Result::ok)
        .filter(|e| e.path().join("cage.yaml.j2").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for expected in ["openclaw", "claude-code", "codex"] {
        assert!(names.iter().any(|n| n == expected), "{names:?}");
    }
}

#[test]
fn agent_scaffolds_build_their_own_image() {
    assert!(
        meta("openclaw")["build"]
            .as_sequence()
            .is_some_and(|b| !b.is_empty())
    );
    for name in ["claude-code", "codex"] {
        assert_eq!(
            meta(name)["build"][0]["image"].as_str(),
            Some(format!("localhost/agentcage-scaffold-{name}:latest").as_str())
        );
    }
}

#[test]
fn builtin_scaffolds_have_a_description_and_a_lifecycle() {
    for name in ["claude-code", "codex", "openclaw"] {
        let m = meta(name);
        assert!(
            m["description"].as_str().is_some_and(|d| !d.is_empty()),
            "{name} has no description"
        );
        let lifecycle = m["lifecycle"].as_str().unwrap_or_default();
        assert!(
            ["interactive", "service"].contains(&lifecycle),
            "{name} has lifecycle {lifecycle:?}"
        );
    }
}

// ── scaffolds/<name>/cage.yaml.j2 ────────────────────────────────────────

/// REGRESSION: the ubuntu scaffold's command copies the CA into a
/// root-only directory. On apple-container the workload runs as uid
/// 1000, so without the `|| true` the copy's EACCES would exit the cage
/// before `sleep infinity`, making `agentcage run ubuntu` look like an
/// instant exit.
#[test]
fn ubuntu_scaffold_ca_install_tolerates_eacces() {
    let template = read(&scaffolds_dir().join("ubuntu/cage.yaml.j2"));
    assert!(template.contains("|| true"));
    assert!(template.contains("exec sleep infinity"));
}

fn rendered_text(scaffold: &str) -> String {
    read(
        &repo_root()
            .join("tests/fixtures/scaffold-configs")
            .join(scaffold)
            .join("cage.yaml"),
    )
}

fn rendered(scaffold: &str) -> Value {
    yaml::load(&rendered_text(scaffold)).unwrap_or_else(|e| panic!("{scaffold}: {e}"))
}

fn strs(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .map(|s| s.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn tmpfs_targets(cfg: &Value) -> Vec<&str> {
    strs(&cfg["container"]["tmpfs"])
}

#[test]
fn openclaw_renders_valid_yaml_with_a_build_section() {
    let cfg = rendered("openclaw");
    assert_eq!(cfg["name"].as_str(), Some("demo"));
    assert!(cfg["container"]["image"].as_str().is_some());
    let build = &cfg["container"]["build"];
    assert_eq!(build["containerfile"].as_str(), Some("Containerfile"));
    assert!(build["args"].get("BASE_IMAGE").is_some());
}

#[test]
fn coding_agent_scaffolds_render_valid_yaml() {
    for (name, domain, alias) in [
        ("claude-code", "anthropic.com", "claude"),
        ("codex", "openai.com", "codex"),
    ] {
        let cfg = rendered(name);
        assert_eq!(cfg["name"].as_str(), Some("demo"), "{name}");
        assert_eq!(cfg["lifecycle"].as_str(), Some("interactive"), "{name}");
        assert_eq!(cfg["scaffold"].as_str(), Some(name));
        assert!(cfg.get("container").is_some(), "{name}");
        assert!(strs(&cfg["domains"]["allow"]).contains(&domain), "{name}");
        assert!(cfg["exec_aliases"].get(alias).is_some(), "{name}");
    }
    let claude = rendered("claude-code");
    assert_eq!(strs(&claude["container"]["command"]), ["sleep", "infinity"]);
    assert!(claude["help"].as_str().is_some_and(|h| !h.is_empty()));
}

/// The OAuth token rule ships commented out: present as guidance, but not
/// active (an active rule would make `cage create` demand the secret). Its
/// placeholder still renders as a concrete entropic token, so uncommenting
/// it yields a ready-to-use config.
#[test]
fn claude_code_secret_injection_and_inactive_oauth_rule() {
    let text = rendered_text("claude-code");
    assert!(text.contains("#- env: CLAUDE_CODE_OAUTH_TOKEN"));
    let marker = "agentcage:secret:CLAUDE_CODE_OAUTH_TOKEN:";
    let token = &text[index_of(&text, marker) + marker.len()..];
    assert!(
        token.len() >= 32
            && token[..32]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "the commented placeholder carries a 32-hex token"
    );
    let cfg = rendered("claude-code");
    let active: Vec<&str> = cfg["secret_injection"]
        .as_sequence()
        .expect("secret_injection")
        .iter()
        .filter_map(|r| r["env"].as_str())
        .collect();
    assert_eq!(active, ["ANTHROPIC_API_KEY"]);
}

/// Scaffolds that bind-mount `${PROJECT_DIR}:/workspace:rw`.
const WORKSPACE_BINDMOUNT_SCAFFOLDS: [&str; 7] = [
    "arch",
    "busybox",
    "claude-code",
    "codex",
    "debian",
    "pi",
    "ubuntu",
];

fn mask<'a>(cfg: &'a Value, target: &str) -> Option<&'a str> {
    tmpfs_targets(cfg)
        .into_iter()
        .find(|e| e.split(':').next() == Some(target))
}

/// Every workspace-bind-mount scaffold masks `/workspace/.git/hooks/`
/// (noexec) so a caged agent cannot plant a hook the next host-side `git
/// commit` runs as the host user (#170).
#[test]
fn git_hooks_mask_present() {
    for scaffold in WORKSPACE_BINDMOUNT_SCAFFOLDS {
        let text = rendered_text(scaffold);
        assert!(
            text.contains("${PROJECT_DIR}:/workspace:rw"),
            "{scaffold} no longer bind-mounts the workspace; update the mask set"
        );
        let cfg = rendered(scaffold);
        let hooks = mask(&cfg, "/workspace/.git/hooks/")
            .unwrap_or_else(|| panic!("{scaffold} lacks the .git/hooks mask (#170)"));
        assert!(hooks.contains("noexec"), "{scaffold}: {hooks:?}");
    }
}

/// claude-code also masks `/workspace/.claude/` so a caged agent cannot
/// plant a `settings.json` hooks block another cage honours (#173).
#[test]
fn claude_code_dotclaude_mask_present() {
    let cfg = rendered("claude-code");
    let dotclaude = mask(&cfg, "/workspace/.claude/").expect("the .claude mask (#173)");
    assert!(dotclaude.contains("noexec"), "{dotclaude:?}");
}

/// openclaw mounts /workspace from a named volume, not a host bind, so it
/// has no host `.git/hooks/` to pivot to and must not grow the mask.
#[test]
fn openclaw_exempt_from_git_hooks_mask() {
    assert!(!rendered_text("openclaw").contains("${PROJECT_DIR}:/workspace"));
    assert!(mask(&rendered("openclaw"), "/workspace/.git/hooks/").is_none());
}

/// codex and pi read no project-level executable config the way Claude
/// Code reads `.claude/settings.json`, so they get the hooks mask only.
#[test]
fn other_agent_scaffolds_have_no_dotclaude_mask() {
    for scaffold in ["codex", "pi"] {
        let cfg = rendered(scaffold);
        assert!(
            !tmpfs_targets(&cfg)
                .iter()
                .any(|e| e.contains("/workspace/.claude/")),
            "{scaffold}"
        );
    }
}

/// The project-level `.claude/` is masked; the cage's own HOME `.claude`
/// (credentials, CLAUDE.md, in-cage settings) must not be, or `claude
/// login` breaks.
#[test]
fn claude_code_home_dotclaude_not_masked() {
    let cfg = rendered("claude-code");
    assert!(mask(&cfg, "/home/node/.claude").is_none());
    assert!(mask(&cfg, "/home/node/.claude/").is_none());
}
