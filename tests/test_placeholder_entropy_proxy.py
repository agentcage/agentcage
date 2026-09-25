"""The injector must never activate an empty placeholder — egress side.

Split out of ``tests/test_placeholder_entropy.py`` (RUST-PORT-PLAN.md §2.4):
``secret_injector`` runs inside the egress container and stays Python, while
the placeholder generation, config parsing, quadlet rendering and CLI column it
was filed next to are host code and become Rust. Test names are unchanged so
failures stay greppable against history.
"""


class TestInjectorEmptyPlaceholderGuard:

    def test_empty_placeholder_rule_skipped(self, monkeypatch):
        """`"" in text` is always True and `text.replace("", v)` corrupts
        content — an empty placeholder must never become an active rule."""
        monkeypatch.setenv("MY_KEY", "real-value")
        from agentcage.data.proxy.secret_injector import SecretInjector
        inj = SecretInjector()
        inj.configure([{"env": "MY_KEY", "placeholder": ""}])
        assert inj.rules == []

    def test_normal_rule_kept(self, monkeypatch):
        monkeypatch.setenv("MY_KEY", "real-value")
        from agentcage.data.proxy.secret_injector import SecretInjector
        inj = SecretInjector()
        inj.configure([
            {"env": "MY_KEY",
             "placeholder": "agentcage:secret:MY_KEY:0123456789abcdef0123456789abcdef"},
        ])
        assert len(inj.rules) == 1
