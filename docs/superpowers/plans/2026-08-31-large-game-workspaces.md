# Phase 8A Large Game Workspaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make full-size PSP games practical to analyze locally by adding deterministic external workspaces, resumable whole-game analysis, and small provenance-locked analysis packs while actively preventing retail/runtime payloads from entering the repository.

**Architecture:** Add a focused `workspace.py` layer for source enumeration, per-file hashing, machine-local source locators, and cached analysis state; extend the existing game-project path to accept extracted PSP directories as well as ISO/CSO inputs; add `analysis_pack.py` for deterministic bounded exports. Keep Phase 7 analyzers authoritative and add a standalone tracked-content guard used by CI.

**Tech Stack:** Python >=3.10, standard library (`argparse`, `dataclasses`, `hashlib`, `json`, `pathlib`, `shutil`, `zipfile`), existing `pycdlib`/CSO support, existing Phase 7 analyzers, pytest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-31-large-game-workspaces-design.md`

## Global Constraints

- Keep retail PSP images, extracted commercial payloads, save states, and raw runtime dumps outside Git-managed outputs.
- Do not add Git LFS, remote storage, PSP decryption/decompression, or title-specific archive parsers.
- Preserve existing `game`, `game-project`, single-module, and Phase 7 APIs/behavior for existing callers.
- Portable manifests/packs must contain no absolute host paths and no timestamps in identity-bearing metadata.
- SHA-256 is the content identity for source files and exported binary evidence.
- Read/hash/copy large files in bounded chunks; do not require whole-file reads for workspace preparation or pack copying.
- All paths derived from PSP/source logical paths must reject absolute paths, `..`, traversal, and symlink escape.
- Workspace metadata and analysis-state files must be written transactionally before being considered complete.
- Use only synthetic fixtures in tests; never add retail game/runtime data.

---

### Task 1: Local workspace, extracted-directory support, deterministic manifests, and resume state

**Files:**
- Create: `src/pspdisasm/workspace.py`
- Modify: `src/pspdisasm/disc.py`
- Modify: `src/pspdisasm/game_project.py`
- Modify: `src/pspdisasm/errors.py`
- Modify: `src/pspdisasm/__init__.py`
- Create: `tests/test_workspace.py`
- Modify: `tests/test_game_project.py`
- Modify: `tests/test_public_api.py`

**Interfaces:**
- Produces `WorkspaceFileRecord`, `GameWorkspaceManifest`, `WorkspaceAnalysisResult`.
- Produces `prepare_game_workspace(source: Path | str, workspace_dir: Path | str) -> GameWorkspaceManifest`.
- Produces `analyze_game_workspace(workspace_dir: Path | str, *, nid_databases: Iterable[Path | str] = ()) -> WorkspaceAnalysisResult`.
- Produces `load_game_workspace(workspace_dir: Path | str) -> GameWorkspaceManifest`.
- Extends `generate_game_project()` so `source` may be an ISO/CSO file or an already-extracted PSP directory without changing existing ISO/CSO behavior.

- [ ] **Step 1: Write failing workspace-manifest tests**

Create `tests/test_workspace.py` with an extracted synthetic tree containing `PSP_GAME/PARAM.SFO`, `PSP_GAME/SYSDIR/EBOOT.BIN`, a second binary/resource, and a nested resource. Use `build_allegrex_elf32()` and the existing synthetic SFO builder pattern.

Assert after:

```python
manifest = prepare_game_workspace(source_tree, workspace)
```

that:

```python
assert manifest.source_kind == "directory"
assert manifest.schema_version == 1
assert [record.path for record in manifest.files] == sorted(
    [record.path for record in manifest.files], key=str.casefold
)
assert all(len(record.sha256) == 64 for record in manifest.files)
assert all(not Path(record.path).is_absolute() for record in manifest.files)
assert (workspace / "workspace.json").exists()
assert (workspace / "manifests/files.json").exists()
assert (workspace / ".pspdisasm-local.json").exists()
```

Read `workspace.json` and `manifests/files.json` as text and assert `str(source_tree.resolve())` is absent from both. Assert the absolute source exists only in `.pspdisasm-local.json`.

Add a determinism test that creates the same synthetic tree under two different absolute roots and asserts the two portable `workspace.json` and `manifests/files.json` payloads are byte-for-byte equal.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_workspace.py
```

Expected: import/collection failure because `pspdisasm.workspace` does not exist.

- [ ] **Step 3: Implement the workspace schema and transactional writers**

In `workspace.py`, define:

```python
WORKSPACE_SCHEMA_VERSION = 1
ANALYSIS_SCHEMA_VERSION = 1
_HASH_CHUNK_BYTES = 1024 * 1024

@dataclass(frozen=True, slots=True)
class WorkspaceFileRecord:
    path: str
    size: int
    sha256: str
    source_kind: str
    classification: str
    executable_kind: str = "unknown"
    analysis_state: str = "pending"
    analysis_version: int = ANALYSIS_SCHEMA_VERSION

@dataclass(slots=True)
class GameWorkspaceManifest:
    schema_version: int
    toolkit_version: str
    source_kind: str
    source_name: str
    source_identity: str
    files: list[WorkspaceFileRecord]

@dataclass(slots=True)
class WorkspaceAnalysisResult:
    workspace_dir: Path
    analysis_dir: Path
    analysis_key: str
    reused: bool
    game_project: GameProjectResult
```

Implement `_sha256_stream(handle)`, `_atomic_write_text(path, text)`, `_safe_logical_path(path)`, canonical JSON with `indent=2`, `sort_keys=True`, and a trailing newline. `source_identity` is SHA-256 of canonical file-record identity data, not an absolute path.

Portable `workspace.json` contains source kind/name/identity/schema/tool version only. `.pspdisasm-local.json` contains the absolute source locator and is explicitly non-portable.

- [ ] **Step 4: Implement streaming enumeration for directory and ISO/CSO sources**

For directories:

- recursively enumerate regular files only;
- normalize paths with `relative_to(root).as_posix()`;
- reject symlinks rather than following them;
- read the first four bytes for executable classification;
- classify `PSP_GAME/SYSDIR/EBOOT.BIN`/`BOOT.BIN`, PRX/ELF-like modules, PARAM.SFO/metadata, and remaining files consistently with Phase 7A semantics;
- hash each file in 1 MiB chunks.

For ISO/CSO:

- call `scan_game_disc(source)` for authoritative logical path/classification metadata;
- reopen the image once with existing `open_disc_stream()` and `pycdlib`;
- walk ISO entries deterministically and hash each member from its ISO file stream in 1 MiB chunks;
- join hashes back to the Phase 7A records by normalized logical path;
- never extract members during `prepare_game_workspace()`.

- [ ] **Step 5: Add and test extracted-directory whole-game support**

Add failing tests to `tests/test_game_project.py` that materialize a valid extracted PSP tree and call:

```python
result = generate_game_project(source_tree, output)
```

Assert one decrypted boot module is analyzed, known/unknown resource counts are produced, and the original source tree remains unchanged.

Implement `scan_game_directory()` and `extract_directory_resources()` in `disc.py`. `scan_game_directory(source, output_dir)` should mirror only executable candidates beneath `output/modules/...`; resource extraction should stream-copy resources beneath `output/resources/files/...`. Update `generate_game_project()` to dispatch to the directory helpers only when `source_path.is_dir()`; retain the existing ISO/CSO code path unchanged.

- [ ] **Step 6: Implement workspace analysis keys and resume behavior**

`analyze_game_workspace()` must:

1. load and validate `workspace.json` and `.pspdisasm-local.json`;
2. reject unsupported schema versions or missing source;
3. compute an analysis key from `source_identity`, analysis schema version, toolkit version, and normalized NID database identities;
4. reuse `analysis/state.json` only when the key matches and required `analysis/game_project/metadata/game_analysis.json` exists;
5. otherwise run `generate_game_project(source, workspace / "analysis/game_project", ...)`;
6. write `analysis/state.json` transactionally only after success;
7. update portable per-file analysis state from generated module/resource metadata without embedding absolute host paths.

Add tests that monkeypatch `workspace.generate_game_project` with a call counter: two unchanged calls yield one analysis invocation and `reused is True` on the second call; changing one source file and re-running `prepare_game_workspace()` changes `source_identity` and forces another invocation.

- [ ] **Step 7: Expose stable public APIs and verify Task 1**

Export `GameWorkspaceManifest`, `WorkspaceFileRecord`, `WorkspaceAnalysisResult`, `prepare_game_workspace`, `load_game_workspace`, and `analyze_game_workspace` from `pspdisasm.__init__`.

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_workspace.py tests/test_game_project.py tests/test_public_api.py
```

Expected: all Task 1 tests pass and existing game-project tests remain green.

- [ ] **Step 8: Commit Task 1**

Commit message:

```text
feat: add deterministic local PSP workspaces
```

---

### Task 2: Selective analysis packs and workspace CLI commands

**Files:**
- Create: `src/pspdisasm/analysis_pack.py`
- Modify: `src/pspdisasm/cli.py`
- Modify: `src/pspdisasm/errors.py`
- Modify: `src/pspdisasm/__init__.py`
- Create: `tests/test_analysis_pack.py`
- Create: `tests/test_cli_workspace.py`

**Interfaces:**
- Produces `AnalysisPackResult` and `create_analysis_pack(workspace_dir, output_path, *, module=None, function=None, resource=None, max_bytes=16 * 1024 * 1024, context_bytes=4096)`.
- CLI commands:
  - `pspdisasm prepare-game SOURCE WORKSPACE`
  - `pspdisasm analyze-workspace WORKSPACE [--nid-db FILE ...]`
  - `pspdisasm make-pack WORKSPACE --output PACK.zip [--module PATH] [--function NAME_OR_ADDRESS] [--resource PATH] [--max-bytes N] [--context-bytes N]`

- [ ] **Step 1: Write failing pack determinism/provenance tests**

Prepare and analyze a synthetic workspace, then create a module pack twice at different output paths:

```python
first = create_analysis_pack(workspace, tmp_path / "first.zip", module="PSP_GAME/SYSDIR/EBOOT.BIN")
second = create_analysis_pack(workspace, tmp_path / "second.zip", module="PSP_GAME/SYSDIR/EBOOT.BIN")
```

Assert both ZIP byte streams are identical. Inspect `pack-manifest.json` and assert it contains selector type/value, workspace `source_identity`, logical source path, source file SHA-256, included artifact paths/sizes/SHA-256 values, and no absolute source/workspace paths.

Add tests that reject selector paths containing `..` or absolute paths and reject a selected full module/resource whose bytes would exceed `max_bytes`.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_analysis_pack.py
```

Expected: collection/import failure because `analysis_pack.py` does not exist.

- [ ] **Step 3: Implement deterministic ZIP writing and bounded artifact collection**

Use explicit `ZipInfo` records with a fixed DOS timestamp `(1980, 1, 1, 0, 0, 0)`, deterministic permission bits, normalized forward-slash names, and sorted member order. Never call `ZipFile.write()` with host metadata.

Define:

```python
DEFAULT_PACK_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_CONTEXT_BYTES = 4096

@dataclass(slots=True)
class AnalysisPackResult:
    output_path: Path
    selector_kind: str
    selector_value: str
    artifact_count: int
    total_bytes: int
    manifest_sha256: str
```

Every included artifact is hashed and represented in `pack-manifest.json`. Enforce the byte budget before adding each payload.

- [ ] **Step 4: Implement module, function, and resource selectors**

Module selector:

- resolve an exact logical module path from workspace `files.json` and `analysis/game_project/metadata/game_analysis.json`;
- include the module's normalized analysis record, project `metadata/functions.json`, `symbols.json`, `references.json`, `strings.json`, `executable.json`, `disassembly.json`, `advanced.json`, `data_typing.json`, `asset_discovery.json` when present;
- include the extracted module bytes only when they fit the configured pack budget;
- record original logical path/size/SHA-256 provenance.

Function selector:

- require exactly one analyzable module match when no `--module` is supplied; otherwise require `module` to disambiguate;
- resolve by exact function name or integer address (`int(value, 0)`) from `metadata/functions.json`;
- include only the matched function record, instructions belonging to its `[address, address + size)` range from `disassembly.json`, references touching that range, matching call-graph edges, and bounded surrounding executable bytes up to `context_bytes` on either side;
- record the slice offset/size and parent module SHA-256.

Resource selector:

- resolve exact logical resource path from `game_resources.json`/workspace manifest;
- include its normalized resource record plus at most `context_bytes` from the file start by default;
- include the complete resource only when it fits `max_bytes` and is explicitly selected under the configured budget;
- include related embedded/container metadata records when their `parent_path` matches.

All selectors must reject ambiguous, missing, traversal, or provenance-mismatched targets with a dedicated `WorkspaceError`/`AnalysisPackError`.

- [ ] **Step 5: Add workspace CLI commands test-first**

Create `tests/test_cli_workspace.py`. Assert:

```python
assert main(["prepare-game", str(source), str(workspace)]) == 0
assert main(["analyze-workspace", str(workspace)]) == 0
assert main([
    "make-pack", str(workspace),
    "--module", "PSP_GAME/SYSDIR/EBOOT.BIN",
    "--output", str(pack),
]) == 0
```

Verify stdout reports source kind/file count/source identity for preparation, reuse state plus game-project counts for analysis, and artifact count/total bytes/manifest SHA-256 for pack creation.

Implement the three argparse subcommands without changing existing command arguments.

- [ ] **Step 6: Expose pack APIs and verify Task 2**

Export `AnalysisPackResult` and `create_analysis_pack` from `pspdisasm.__init__` and extend `tests/test_public_api.py`.

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_analysis_pack.py tests/test_cli_workspace.py tests/test_public_api.py
```

Expected: all Task 2 tests pass.

- [ ] **Step 7: Commit Task 2**

Commit message:

```text
feat: add selective PSP analysis packs
```

---

### Task 3: Repository payload guard, scale/safety hardening, documentation, and full verification

**Files:**
- Create: `tools/check_repository_payloads.py`
- Modify: `.gitignore`
- Modify: `.github/workflows/tests.yml`
- Create: `tests/test_repository_guard.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_analysis_pack.py`
- Modify: `README.md`
- Create: `docs/phase8a-large-game-workspaces.md`

**Interfaces:**
- Produces `python tools/check_repository_payloads.py` with exit code `0` for allowed tracked repository content and non-zero for blocked payloads.
- Default opaque-binary tracked-file threshold: `16 * 1024 * 1024` bytes.
- Explicit small-fixture allowlist is path-based and must stay within `tests/`.

- [ ] **Step 1: Write failing repository-guard tests**

Create unit tests around pure helper functions in `tools/check_repository_payloads.py` using synthetic tracked-file metadata rather than invoking a real Git repository.

Assert blocked suffixes include at least:

```text
.iso .cso .zso .dax .ppst .savestate .memdump
```

Assert workspace/cache path components such as `.pspdisasm-workspace`, `workspace/cache`, and `resources/files` are blocked when tracked outside an explicit synthetic fixture allowlist. Assert an opaque `.bin` over 16 MiB is blocked while a small fixture under `tests/fixtures/` is allowed.

- [ ] **Step 2: Run focused guard tests and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_repository_guard.py
```

Expected: failure because the guard helper does not exist.

- [ ] **Step 3: Implement tracked-content guard and CI integration**

`tools/check_repository_payloads.py` must obtain tracked paths with:

```python
subprocess.run(
    ["git", "ls-files", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout.split(b"\0")
```

For each tracked regular file, reject blocked runtime/game suffixes and reject opaque binary files over 16 MiB unless the path matches an explicit small synthetic-fixture allowlist. Print one deterministic violation per line and return exit code `1` if any violation exists.

Update GitHub Actions before pytest:

```yaml
- name: Reject retail/runtime payloads
  run: python tools/check_repository_payloads.py
```

- [ ] **Step 4: Expand `.gitignore` for local game workspaces/runtime data**

Add patterns for ISO/CSO/ZSO/DAX images, `.ppst`, memory dumps, local workspace markers/caches/packs, and common generated full-game analysis trees. Keep test fixture paths usable by allowing only generated-at-test-time content; no real binary fixtures are committed.

- [ ] **Step 5: Add hardening tests for large streaming, symlinks, and cache invalidation**

In `tests/test_workspace.py`, create a synthetic multi-file directory whose total size is several MiB using repeated generated bytes. Monkeypatch/read wrappers to assert hashing requests are capped at `_HASH_CHUNK_BYTES` and no `.read()` without a size is used on source payloads during preparation.

Add tests that a source symlink is rejected, a workspace-local source locator pointing outside/missing is rejected cleanly, and an unsupported workspace schema raises `WorkspaceError` without modifying analysis state.

In `tests/test_analysis_pack.py`, add traversal/symlink-output tests and verify the max-byte budget is enforced before a partially completed output ZIP is left behind.

- [ ] **Step 6: Document Phase 8A and current status**

Update README status to Phase 8A and document:

```bash
pspdisasm prepare-game /path/to/game.iso /path/to/game-workspace
pspdisasm analyze-workspace /path/to/game-workspace
pspdisasm make-pack /path/to/game-workspace \
  --module PSP_GAME/SYSDIR/EBOOT.BIN \
  --output eboot-analysis.zip
```

State explicitly that the original game remains local, `.pspdisasm-local.json` is machine-local, packs are bounded evidence bundles, and existing `game-project` remains supported.

Add `docs/phase8a-large-game-workspaces.md` describing schemas, resume-key behavior, pack provenance, size defaults, repository guard policy, and limitations.

- [ ] **Step 7: Run complete quality verification**

Run:

```bash
python tools/check_repository_payloads.py
PYTHONPATH=src python -m pytest -q
```

Expected: repository guard passes and the entire legacy + Phase 8A test suite passes.

Also run a clean CLI smoke sequence against a synthetic extracted directory:

```bash
pspdisasm prepare-game synthetic_game synthetic_workspace
pspdisasm analyze-workspace synthetic_workspace
pspdisasm make-pack synthetic_workspace --module PSP_GAME/SYSDIR/EBOOT.BIN --output pack.zip
```

Verify no portable JSON/ZIP member contains the absolute synthetic source path.

- [ ] **Step 8: Commit Task 3**

Commit message:

```text
chore: harden large PSP workspace workflow
```

- [ ] **Step 9: Final branch/PR verification**

Confirm the branch diff contains only source, tests, docs, CI configuration, and small text metadata. Confirm no ISO/CSO/retail binary/save-state/memory-dump payload is present. Open/update the Phase 8A PR, require exact-head CI success, audit review threads, and merge only the verified head SHA according to the established project merge gate.
