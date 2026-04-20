"""Tests for registry.resolve_build_args — tag resolution semantics."""

from agentcage.registry import resolve_build_args


def _fake_resolver(mapping: dict[str, str | None]):
    """Return a resolver that looks tags up in *mapping*, tracking calls."""
    calls: list[str] = []

    def _resolve(base: str) -> str | None:
        calls.append(base)
        return mapping.get(base)

    _resolve.calls = calls  # type: ignore[attr-defined]
    return _resolve


class TestResolveBuildArgsEmpty:
    def test_empty_args(self):
        resolved, changes = resolve_build_args({}, {}, resolver=lambda _: "ignored")
        assert resolved == {}
        assert changes == []

    def test_no_scaffold_no_changes(self):
        resolver = _fake_resolver({})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1"}, resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:v1"}
        assert changes == []
        assert resolver.calls == []  # pinned user-added, no resolve


class TestScaffoldUntagged:
    """Scaffold declares an untagged image ref — auto-bump semantics."""

    def test_resolves_and_bumps_existing_pin(self):
        resolver = _fake_resolver({"ghcr.io/openclaw/openclaw": "2026.4.1-1"})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1"},
            {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.4.1-1"}
        assert changes == [(
            "BASE_IMAGE",
            "ghcr.io/openclaw/openclaw:2026.3.13-1",
            "ghcr.io/openclaw/openclaw:2026.4.1-1",
        )]
        assert resolver.calls == ["ghcr.io/openclaw/openclaw"]

    def test_same_tag_no_change(self):
        resolver = _fake_resolver({"ghcr.io/foo/bar": "v2"})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v2"},
            {"BASE_IMAGE": "ghcr.io/foo/bar"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:v2"}
        assert changes == []

    def test_resolver_failure_preserves_stored_pin(self):
        """REGRESSION: offline `cage update` must NOT un-pin a working build."""
        resolver = _fake_resolver({"ghcr.io/foo/bar": None})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1"},
            {"BASE_IMAGE": "ghcr.io/foo/bar"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:v1"}
        assert changes == []

    def test_resolver_failure_with_untagged_stored_stays_untagged(self):
        resolver = _fake_resolver({"ghcr.io/foo/bar": None})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar"},
            {"BASE_IMAGE": "ghcr.io/foo/bar"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar"}
        assert changes == []

    def test_migrates_on_scaffold_base_rename(self):
        """Scaffold author changed the image base — auto-migrate."""
        resolver = _fake_resolver({"ghcr.io/new/base": "v2"})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/old/base:v1"},
            {"BASE_IMAGE": "ghcr.io/new/base"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/new/base:v2"}
        assert changes == [(
            "BASE_IMAGE",
            "ghcr.io/old/base:v1",
            "ghcr.io/new/base:v2",
        )]
        # Only new base queried — never resolves the old one
        assert resolver.calls == ["ghcr.io/new/base"]


class TestScaffoldPinned:
    """Scaffold declares an explicit tag — respect author's pin."""

    def test_respects_pin_no_resolver_call(self):
        resolver = _fake_resolver({"ghcr.io/foo/bar": "v99"})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1.2.3"},
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1.2.3"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:v1.2.3"}
        assert changes == []
        assert resolver.calls == []  # pin is respected, no resolution

    def test_migrates_stored_to_scaffold_pin(self):
        """Scaffold bumped its pin — stored follows."""
        resolver = _fake_resolver({})
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1.0.0"},
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1.2.3"},
            resolver=resolver,
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:v1.2.3"}
        assert changes == [(
            "BASE_IMAGE",
            "ghcr.io/foo/bar:v1.0.0",
            "ghcr.io/foo/bar:v1.2.3",
        )]
        assert resolver.calls == []


class TestUserAdded:
    """Args not declared in scaffold — user-added, light-touch semantics."""

    def test_pinned_user_arg_passthrough(self):
        resolver = _fake_resolver({"docker.io/foo/bar": "v2"})
        resolved, changes = resolve_build_args(
            {"CUSTOM": "docker.io/foo/bar:v1"},
            {},  # no scaffold entry for CUSTOM
            resolver=resolver,
        )
        assert resolved == {"CUSTOM": "docker.io/foo/bar:v1"}
        assert changes == []
        assert resolver.calls == []

    def test_untagged_registry_like_user_arg_resolves(self):
        resolver = _fake_resolver({"docker.io/foo/bar": "v2"})
        resolved, changes = resolve_build_args(
            {"CUSTOM": "docker.io/foo/bar"},
            {},
            resolver=resolver,
        )
        assert resolved == {"CUSTOM": "docker.io/foo/bar:v2"}
        assert changes == [(
            "CUSTOM",
            "docker.io/foo/bar",
            "docker.io/foo/bar:v2",
        )]

    def test_untagged_non_registry_user_arg_passthrough(self):
        """A bare 'foo' isn't a registry ref — don't touch it."""
        resolver = _fake_resolver({})
        resolved, changes = resolve_build_args(
            {"VERSION": "1.2.3"},
            {},
            resolver=resolver,
        )
        assert resolved == {"VERSION": "1.2.3"}
        assert changes == []
        assert resolver.calls == []

    def test_untagged_user_arg_resolver_failure_passthrough(self):
        resolver = _fake_resolver({"docker.io/foo/bar": None})
        resolved, changes = resolve_build_args(
            {"CUSTOM": "docker.io/foo/bar"},
            {},
            resolver=resolver,
        )
        assert resolved == {"CUSTOM": "docker.io/foo/bar"}
        assert changes == []


class TestMixed:
    def test_scaffold_and_user_args_coexist(self):
        resolver = _fake_resolver({
            "ghcr.io/openclaw/openclaw": "2026.4.1-1",
            "docker.io/me/mine": "v9",
        })
        resolved, changes = resolve_build_args(
            {
                "BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.3.13-1",
                "MY_SIDECAR": "docker.io/me/mine",
                "VERSION_STRING": "1.0.0",
            },
            {"BASE_IMAGE": "ghcr.io/openclaw/openclaw"},
            resolver=resolver,
        )
        assert resolved == {
            "BASE_IMAGE": "ghcr.io/openclaw/openclaw:2026.4.1-1",
            "MY_SIDECAR": "docker.io/me/mine:v9",
            "VERSION_STRING": "1.0.0",
        }
        assert sorted(changes) == sorted([
            (
                "BASE_IMAGE",
                "ghcr.io/openclaw/openclaw:2026.3.13-1",
                "ghcr.io/openclaw/openclaw:2026.4.1-1",
            ),
            (
                "MY_SIDECAR",
                "docker.io/me/mine",
                "docker.io/me/mine:v9",
            ),
        ])


class TestDefaultResolverWiring:
    """Smoke-check that the default resolver is `resolve_latest_tag`."""

    def test_default_resolver_is_used_when_not_provided(self, monkeypatch):
        calls: list[str] = []

        def fake(base: str) -> str | None:
            calls.append(base)
            return "fromreal"

        monkeypatch.setattr("agentcage.registry.resolve_latest_tag", fake)
        resolved, changes = resolve_build_args(
            {"BASE_IMAGE": "ghcr.io/foo/bar:v1"},
            {"BASE_IMAGE": "ghcr.io/foo/bar"},
        )
        assert resolved == {"BASE_IMAGE": "ghcr.io/foo/bar:fromreal"}
        assert calls == ["ghcr.io/foo/bar"]
