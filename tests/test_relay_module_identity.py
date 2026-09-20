"""The relay validator is one file reached by two import paths.

Lifted out of ``test_contract_fixtures.py``, which asserts each side
against the recorded fixture and deliberately never compares the two to
each other. This one has to: it is the assertion that says WHY the host
half of that file could stop asserting the relay validator at all.

``config.py`` imports the validator as
``agentcage.data.proxy.relays._validate``; the egress container imports
it as ``relays._validate``, because it ships without the CLI package on
the path. Today both resolve to the same file, so the two are two
``sys.modules`` entries over one source. After the port they are a Rust
implementation and a Python one, held together by
``tests/fixtures/contracts/validate_relay_entry.json`` instead — and
this file goes with the seam it describes.
"""

from __future__ import annotations

from pathlib import Path


class TestRelayModuleIdentity:
    def test_the_two_import_paths_are_distinct_module_objects(self):
        """Not a tautology: they are two entries in ``sys.modules``.

        If this ever starts failing because one import path disappeared,
        the contract has changed shape and the fixture's ``implementations``
        block needs updating with it.
        """
        import relays._validate as proxy_side
        from agentcage.data.proxy.relays import _validate as host_side

        assert proxy_side is not host_side
        assert Path(proxy_side.__file__) == Path(host_side.__file__)
