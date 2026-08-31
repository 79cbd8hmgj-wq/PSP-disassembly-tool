from __future__ import annotations

from tools.check_repository_payloads import OPAQUE_BINARY_LIMIT, violation_for


def test_repository_guard_blocks_disc_and_runtime_payload_suffixes():
    for path in (
        "game.iso",
        "game.cso",
        "game.zso",
        "game.dax",
        "runtime.ppst",
        "runtime.savestate",
        "runtime.memdump",
    ):
        assert violation_for(path, 1) is not None, path


def test_repository_guard_blocks_generated_workspace_payload_trees():
    for path in (
        ".pspdisasm-workspace/cache/module.bin",
        "workspace/cache/module.bin",
        "workspace/analysis/game_project/resources/files/TEXTURE.PNG",
        "resources/files/TEXTURE.PNG",
    ):
        assert violation_for(path, 1) is not None, path


def test_repository_guard_rejects_oversized_opaque_binary_but_allows_small_fixture():
    assert violation_for("assets/data.bin", OPAQUE_BINARY_LIMIT + 1) is not None
    assert violation_for("tests/fixtures/tiny.bin", 1024) is None


def test_repository_guard_allows_normal_source_and_documentation():
    assert violation_for("src/pspdisasm/workspace.py", 100_000) is None
    assert violation_for("README.md", 100_000) is None
    assert violation_for("docs/phase8a-large-game-workspaces.md", 100_000) is None
