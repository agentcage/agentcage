"""Tests for stable deployment fingerprint computation."""

from __future__ import annotations

from agentcage.fingerprint import compute_fingerprint


BASE_YAML = """\
# operator comment
name: demo
container:
  image: example/app:latest
  env:
    B: two
    A: one
"""


def _fingerprint(
    cage_yaml: str = BASE_YAML,
    *,
    image_digest: str = "sha256:image-one",
    quadlet: str = "[Container]\nImage=example/app:latest\n",
    scaffold_version: str = "scaffold-v1",
):
    return compute_fingerprint(
        cage_yaml,
        resolved_config={
            "name": "demo",
            "container": {"image": "example/app:latest"},
        },
        units={"demo-cage.container": quadlet},
        image_digests={"example/app:latest": image_digest},
        scaffold_version=scaffold_version,
    )


def test_identical_inputs_have_same_fingerprint():
    assert _fingerprint() == _fingerprint()


def test_yaml_comments_whitespace_and_mapping_order_are_ignored():
    reordered = """\
container: # an inline comment is irrelevant
  env: {A: one, B: two}
  image: example/app:latest

name: demo
"""
    assert _fingerprint()["fingerprint"] == _fingerprint(reordered)["fingerprint"]


def test_changed_image_digest_changes_fingerprint():
    assert _fingerprint()["fingerprint"] != _fingerprint(
        image_digest="sha256:image-two"
    )["fingerprint"]


def test_changed_quadlet_changes_fingerprint():
    assert _fingerprint()["fingerprint"] != _fingerprint(
        quadlet="[Container]\nImage=example/app:v2\n"
    )["fingerprint"]


def test_changed_scaffold_version_changes_fingerprint():
    assert _fingerprint()["fingerprint"] != _fingerprint(
        scaffold_version="scaffold-v2"
    )["fingerprint"]
