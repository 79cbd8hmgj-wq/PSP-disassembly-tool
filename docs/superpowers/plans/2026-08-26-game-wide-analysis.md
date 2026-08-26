# Phase 7B Game-Wide Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a full-disc PSP analysis command that inventories ISO/CSO images, analyzes every usable decrypted module, creates per-module decompilation projects, links modules, and writes deterministic game-level reports.

**Architecture:** Add a focused `game_project.py` orchestrator that composes the existing Phase 7A scanner, Phase 1/2 analyzers, Phase 3 project generator, and Phase 6B linker. Keep the existing `game` scan-only command unchanged and expose the heavier workflow as `game-project`.

**Tech Stack:** Python 3.11+, argparse, dataclasses, pathlib, pycdlib, lz4, existing pspdisasm analyzer/disassembler/project/linker APIs, pytest.

**Spec:** `docs/superpowers/specs/2026-08-26-game-wide-analysis-design.md`

## Global Constraints

- Do not implement PSP cryptographic decryption.
- Do not add new NID heuristics; reuse the existing linker rules exactly.
- Keep Phase 7A `pspdisasm game` behavior unchanged.
- Process modules and write reports deterministically.
- Isolate module-local parse/disassembly/project failures so other modules continue.
- Treat missing global analysis engines as fatal for `game-project`.
- Preserve containment safety for all mirrored extracted/project paths.
- Use only synthetic PSP-like fixtures in tests; no commercial game data.

---

### Task 1: Core game-project orchestration and module status model

**Files:**
- Create: `src/pspdisasm/game_project.py`
- Create: `tests/test_game_project.py`

**Interfaces:**
- Consumes: `scan_game_disc(source, output_dir)`, `analyze_file(path)`, `disassemble_file(path)`, `generate_project(path, output, nid_databases=...)`.
- Produces: `GameModuleAnalysisRecord`, `GameProjectAnalysis`, `GameProjectResult`, `generate_game_project(source, output_dir, *, nid_databases=())`.

- [ ] **Step 1: Write failing integration tests for analyzed and encrypted modules**

Create `tests/test_game_project.py` with a small ISO builder using `pycdlib`, `tests.fixtures.build_allegrex_elf32()`, and `tests.fixtures.build_psp_container_header()`.

The first test must build an ISO containing:

```text
PSP_GAME/PARAM.SFO
PSP_GAME/SYSDIR/EBOOT.BIN     # build_allegrex_elf32()
PSP_GAME/USRDIR/LOCKED.PRX    # build_psp_container_header()
```

Call:

```python
result = generate_game_project(image, output)
```

Assert:

```python
assert result.module_count == 2
assert result.analyzed_count == 1
assert result.needs_decryption_count == 1
assert result.failed_count == 0
assert (output / "projects/PSP_GAME/SYSDIR/EBOOT.BIN/splat.yaml").exists()
assert not (output / "projects/PSP_GAME/USRDIR/LOCKED.PRX").exists()
```

Load `metadata/game_analysis.json` and assert the boot record has `status == "analyzed"`, the locked PRX has `status == "needs_decryption"`, and the encrypted record has no `project_path`.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_game_project.py
```

Expected: collection/import failure because `pspdisasm.game_project` and `generate_game_project` do not exist.

- [ ] **Step 3: Implement the minimal orchestration records and safe mirrored path helper**

In `game_project.py`, add:

```python
@dataclass(slots=True)
class GameModuleAnalysisRecord:
    path: str
    extracted_path: str | None
    executable_kind: str
    is_boot: bool
    status: str
    module_name: str | None = None
    project_path: str | None = None
    function_count: int = 0
    symbol_count: int = 0
    reference_count: int = 0
    string_count: int = 0
    warnings: list[str] = field(default_factory=list)

@dataclass(slots=True)
class GameProjectAnalysis:
    source_name: str
    title: str | None
    disc_id: str | None
    image_format: str
    boot_path: str | None
    modules: list[GameModuleAnalysisRecord]
    links: ModuleLinkAnalysis
    warnings: list[str] = field(default_factory=list)

@dataclass(slots=True)
class GameProjectResult:
    output_dir: Path
    analysis_path: Path
    links_path: Path
    module_count: int
    analyzed_count: int
    needs_decryption_count: int
    failed_count: int
```

Add a containment helper that rejects absolute paths, `..`, or any resolved target outside the supplied root. Mirror logical module paths under `projects/` without flattening basenames.

- [ ] **Step 4: Implement module processing**

`generate_game_project()` must:

1. call `scan_game_disc(source, output)`;
2. sort `manifest.modules` by `record.path.casefold()`;
3. validate/resolve each `record.output_path` under `output`;
4. call `analyze_file()`;
5. record `needs_decryption` and skip disassembly/project generation when required;
6. otherwise call `disassemble_file()` and `generate_project()`;
7. collect counts from the disassembly result;
8. isolate `ParseError`, `DisassemblyError`, `ValueError`, and ordinary `OSError` as module-local `failed` records;
9. allow `EngineUnavailableError` to propagate.

Use the module's normalized PSP name from `model.module_info.name` when available, otherwise the container header module name when available.

- [ ] **Step 5: Run the focused test and verify GREEN**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_game_project.py
```

Expected: the analyzed/encrypted integration test passes.

- [ ] **Step 6: Commit**

Commit message:

```text
feat: orchestrate game-wide PSP module analysis
```

---

### Task 2: Global module linking, failure isolation, and deterministic reports

**Files:**
- Modify: `src/pspdisasm/game_project.py`
- Modify: `tests/test_game_project.py`

**Interfaces:**
- Consumes: successful `ModuleAnalysisInput(model, disassembly)` values gathered during Task 1 and `load_nid_databases(nid_databases)`.
- Produces: `metadata/game_analysis.json`, `metadata/module_links.json`, `metadata/propagated_symbols.json`.

- [ ] **Step 1: Add failing tests for linker input and isolated module failure**

Add a test that monkeypatches `game_project.link_modules` with a recorder function returning an empty `ModuleLinkAnalysis`. Feed two analyzable extracted candidates and assert the recorder receives two `ModuleAnalysisInput` records in disc-path order.

Add a second test where `game_project.disassemble_file` raises `DisassemblyError("synthetic failure")` for one secondary module only. Assert:

```python
assert result.analyzed_count == 1
assert result.failed_count == 1
```

and `game_analysis.json` contains a `failed` module record whose warnings include `synthetic failure` while the valid module project still exists.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_game_project.py
```

Expected: failures because global linking/report persistence and failure-count behavior are incomplete.

- [ ] **Step 3: Implement one global linker pass**

Load the NID database once after module processing:

```python
database = load_nid_databases(tuple(nid_databases))
links = link_modules(link_units, database)
```

Do not include `needs_decryption` or `failed` modules in `link_units`.

Append linker warnings to the game-level warning list only through the normalized `links` object; do not duplicate them into every module record.

- [ ] **Step 4: Persist deterministic game-level metadata**

Create `output/metadata` if needed and write:

```text
metadata/game_analysis.json
metadata/module_links.json
metadata/propagated_symbols.json
```

Use `dataclasses.asdict()`, `json.dumps(..., indent=2, sort_keys=True)`, and a trailing newline.

Ensure module records remain sorted by logical path and linker output keeps the existing linker's deterministic ordering.

- [ ] **Step 5: Verify focused tests**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_game_project.py
```

Expected: all game-project tests pass.

- [ ] **Step 6: Commit**

Commit message:

```text
feat: link and report analyzed game modules
```

---

### Task 3: Public API and `game-project` CLI

**Files:**
- Modify: `src/pspdisasm/__init__.py`
- Modify: `src/pspdisasm/cli.py`
- Create: `tests/test_cli_game_project.py`

**Interfaces:**
- Consumes: `generate_game_project()` from Task 1/2.
- Produces: public `pspdisasm.generate_game_project` and CLI `pspdisasm game-project INPUT OUTPUT [--nid-db FILE ...]`.

- [ ] **Step 1: Write the failing CLI test**

Build a synthetic ISO with a valid decrypted boot ELF, call:

```python
code = main(["game-project", str(image), str(output)])
```

Assert:

```python
assert code == 0
assert (output / "metadata/game_analysis.json").exists()
assert (output / "metadata/module_links.json").exists()
```

Capture stdout and assert it contains:

```text
Analyzed modules: 1
Needs decryption: 0
Failed modules: 0
Game analysis:
```

Also retain the existing Phase 7A `game` CLI test unchanged to prove scan-only compatibility.

- [ ] **Step 2: Run the CLI test and verify RED**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_cli_game_project.py tests/test_cli_disc.py
```

Expected: argparse rejects `game-project`.

- [ ] **Step 3: Add parser and command dispatch**

In `_parser()` add:

```python
game_project = sub.add_parser(
    "game-project",
    help="Analyze all usable modules in a PSP ISO/CSO and build game-wide decompilation workspaces",
)
game_project.add_argument("input", type=Path)
game_project.add_argument("output", type=Path)
game_project.add_argument(
    "--nid-db",
    type=Path,
    action="append",
    default=[],
    metavar="FILE",
    help="NID JSON or PSPLibDoc-style CSV database; may be repeated and later files win",
)
```

Dispatch with:

```python
result = generate_game_project(args.input, args.output, nid_databases=args.nid_db)
```

Print title/disc identity by reading the persisted analysis or by returning the summary fields needed from the orchestration result. The mandatory summary counters come directly from `GameProjectResult`.

- [ ] **Step 4: Export the API**

Add:

```python
from .game_project import generate_game_project
```

and include `"generate_game_project"` in `__all__`.

- [ ] **Step 5: Verify CLI and public API tests**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_cli_game_project.py tests/test_cli_disc.py tests/test_game_project.py
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit**

Commit message:

```text
feat: expose game-wide analysis command
```

---

### Task 4: Documentation, compatibility, and full verification

**Files:**
- Modify: `README.md`
- Create: `docs/phase7b-game-analysis.md`

**Interfaces:**
- Consumes: final `game-project` CLI/API behavior.
- Produces: user-facing Phase 7B usage and accurate current limitations.

- [ ] **Step 1: Update README current status and commands**

Document Phase 7B with:

```bash
python -m pip install -e '.[analysis,disc]'
pspdisasm game-project GAME.iso game_decomp
pspdisasm game-project GAME.cso game_decomp --nid-db psp_nids.csv
```

Describe the `projects/<logical-disc-path>/` layout and game-level metadata reports.

Remove any limitation claiming game-wide module orchestration is unavailable. Retain explicit limitations for encrypted `~PSP` bodies, recursive arbitrary resource/archive scanning, and cross-module name reinjection into each generated symbol file.

- [ ] **Step 2: Add focused Phase 7B documentation**

`docs/phase7b-game-analysis.md` must explain:

- scan-only `game` vs full `game-project`;
- module statuses (`analyzed`, `needs_decryption`, `failed`);
- mirrored project paths;
- game-level link reports;
- failure isolation;
- encryption boundary;
- deferred recursive resource analysis.

- [ ] **Step 3: Run the full repository test suite**

Run:

```bash
PYTHONPATH=src python -m pytest -q
```

Expected: zero failures. The existing single environment-dependent skip may remain.

- [ ] **Step 4: Inspect the branch diff against `main`**

Verify only the Phase 7B spec/plan, orchestrator, tests, CLI/API wiring, and docs changed. Confirm no source archives or commercial game data were committed.

- [ ] **Step 5: Commit documentation**

Commit message:

```text
docs: document Phase 7B game-wide analysis
```

- [ ] **Step 6: Open/update the Phase 7B pull request and verify its merge ref**

The PR must target `main`, summarize the Phase 7B orchestration boundary, and remain unmerged until the PR merge-ref CI run is green.
