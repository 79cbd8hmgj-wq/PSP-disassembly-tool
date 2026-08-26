# Phase 7D Container Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic profiling and safe parser-driven extraction for unknown PSP game resource containers without inventing proprietary format rules.

**Architecture:** A new neutral `resource_containers.py` module owns fingerprints, parser interfaces, parser selection, entry validation primitives, and family grouping. `game_resources.py` integrates those primitives into the existing whole-disc resource pass, while `game_project.py`, the CLI, exports, and documentation expose counts and parser extension points without changing the default empty parser set.

**Tech Stack:** Python 3.12, dataclasses, pathlib, csv/json, pytest, existing `resource_formats.py` detectors.

**Spec:** `docs/superpowers/specs/2026-08-26-container-intelligence-design.md`

## Global Constraints

- Do not infer a universal archive format from `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, `.PKG`, or similar extensions.
- Built-in proprietary parser set remains empty until a real target format is evidenced.
- Parser acceptance threshold is `>= 0.90`.
- Prefix fingerprint length is 16 bytes; entropy sample is capped at 64 KiB.
- Maximum accepted entries per container is 4096.
- Traversal/symlink containment violations are fatal integrity errors.
- Parser/probe/range failures are resource-local warnings where containment is not violated.
- Output ordering and normalized metadata must be deterministic.

---

### Task 1: Neutral container intelligence primitives

**Files:**
- Create: `src/pspdisasm/resource_containers.py`
- Create: `tests/test_resource_containers.py`

**Interfaces:**
- Produces `ContainerCandidateProfile`, `ContainerFamily`, `ContainerEntry`, `ContainerInspection`, `ResourceContainerParser`.
- Produces `profile_container_candidate(path, logical_path, *, embedded_count=0, bounded_embedded_bytes=0)`.
- Produces `group_container_families(profiles)`.
- Produces `select_container_parser(prefix, logical_path, parsers, *, threshold=0.90)`.

- [ ] **Step 1: Write failing profile/family tests**

Create tests proving a 16-byte fingerprint, deterministic ASCII rendering, bounded entropy calculation, normalized suffix, and stable family grouping by suffix + first four bytes.

- [ ] **Step 2: Run the new test file and verify RED**

Run through branch CI after committing only the tests. Expected failure: `pspdisasm.resource_containers` does not exist.

- [ ] **Step 3: Implement the minimal profile/family types and helpers**

Use dataclasses with slots. Read at most 64 KiB for entropy and the first 16 bytes for the fingerprint. Return deterministic sorted family membership.

- [ ] **Step 4: Add parser-selection tests**

Tests must prove: confidence below 0.90 is rejected; higher confidence wins; equal confidence resolves by parser name; exceptions/non-finite/out-of-range probes are ignored with warnings returned from selection.

- [ ] **Step 5: Implement parser types and deterministic selection**

Selection returns `(parser | None, confidence, warnings)` and never trusts a parser-supplied score outside `[0.0, 1.0]`.

- [ ] **Step 6: Run focused tests GREEN**

Run: `PYTHONPATH=src python -m pytest -q tests/test_resource_containers.py`

Expected: all focused tests pass.

---

### Task 2: Game-resource profiling and reports

**Files:**
- Modify: `src/pspdisasm/game_resources.py`
- Modify: `tests/test_game_resources.py`

**Interfaces:**
- `analyze_game_resources(source_name, output_dir, resources, *, container_parsers=()) -> GameResourceAnalysis`
- `GameResourceAnalysis.container_candidates`
- `GameResourceAnalysis.container_families`
- `GameResourceAnalysis.container_inspections`
- `GameResourceAnalysis.container_entries`

- [ ] **Step 1: Write failing integration tests for unknown profiling**

Extend `test_game_resources.py` so two unknown `.DAT` files sharing the same first four bytes land in one deterministic family while a known PNG remains outside the candidate list.

- [ ] **Step 2: Verify RED in branch CI**

Expected failure: Phase 7D fields/reports are absent.

- [ ] **Step 3: Add profiling to `analyze_game_resources()`**

Profile only loose files whose `detected_format` remains `unknown`, carrying existing embedded-resource counts and bounded known embedded byte totals.

- [ ] **Step 4: Write deterministic candidate outputs**

Add `metadata/container_candidates.json` and `reports/container_candidates.csv`, sorted by logical path. Include family key, suffix, prefix hex/ascii, entropy, size, embedded count, and bounded embedded bytes.

- [ ] **Step 5: Run focused integration tests GREEN**

Run: `PYTHONPATH=src python -m pytest -q tests/test_game_resources.py tests/test_resource_containers.py`

---

### Task 3: Parser inspection and bounded entry extraction

**Files:**
- Modify: `src/pspdisasm/resource_containers.py`
- Modify: `src/pspdisasm/game_resources.py`
- Modify: `tests/test_game_resources.py`

**Interfaces:**
- `ContainerEntry(path: str, offset: int, size: int, metadata: dict[str, object] = {})`
- `ContainerInspection(parser_name: str, format_name: str, confidence: float, entries: list[ContainerEntry], warnings: list[str])`
- `ContainerEntryRecord` in `game_resources.py` records parent path, parser, inner path, range, extracted path, classification fields, metadata, and warnings.

- [ ] **Step 1: Write a failing synthetic-parser extraction test**

Use a local test parser whose probe returns `0.99` and whose inspection exposes a bounded PNG entry. Assert the entry is extracted beneath `resources/containers/<parent>/<inner>` and classified as PNG.

- [ ] **Step 2: Verify RED**

Expected failure: custom parsers are not invoked and no container entry output exists.

- [ ] **Step 3: Implement parser invocation and accepted-entry extraction**

For unknown files only, select a parser, call `inspect()`, validate at most 4096 entries, verify ranges against parent file size, use containment-safe destinations, copy exact byte ranges, and classify entry bytes with `detect_resource_at(..., 0)`.

- [ ] **Step 4: Add out-of-bounds and parser-failure tests**

Out-of-range entries become warnings and are not extracted. Parser `probe()` or `inspect()` exceptions do not abort analysis.

- [ ] **Step 5: Add traversal test**

A parser entry with `/absolute`, `..`, or a symlink-escaping destination raises `ValueError` as a fatal integrity error.

- [ ] **Step 6: Write inspection/entry reports**

Add `metadata/container_inspections.json` and `reports/container_entries.csv`, with deterministic ordering by parent path, parser, offset, and inner path.

- [ ] **Step 7: Run focused tests GREEN**

Run: `PYTHONPATH=src python -m pytest -q tests/test_game_resources.py tests/test_resource_containers.py`

---

### Task 4: Whole-game API/result integration

**Files:**
- Modify: `src/pspdisasm/game_project.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `src/pspdisasm/cli.py`
- Modify: `tests/test_game_project.py`
- Modify: `tests/test_cli_game_project.py`

**Interfaces:**
- `generate_game_project(..., container_parsers=()) -> GameProjectResult`
- Result adds `container_candidate_count`, `container_inspection_count`, `container_entry_count`, `containers_path`.
- Public exports add the Phase 7D parser/entry/inspection types.

- [ ] **Step 1: Write failing game-project counter test**

Build a synthetic ISO containing at least one unknown resource. Assert candidate counts and candidate metadata path exist with no parsers supplied.

- [ ] **Step 2: Verify RED**

Expected failure: Phase 7D result fields are absent.

- [ ] **Step 3: Forward parsers and populate result counters**

Do not change the CLI's default parser set. Programmatic callers may pass title-specific parsers.

- [ ] **Step 4: Extend CLI summary conservatively**

Report container candidates, inspected containers, and extracted container entries. Do not add dynamic Python-module loading flags.

- [ ] **Step 5: Export public interfaces**

Re-export `ContainerEntry`, `ContainerInspection`, `ResourceContainerParser`, and profiling types from `pspdisasm`.

- [ ] **Step 6: Run focused tests GREEN**

Run: `PYTHONPATH=src python -m pytest -q tests/test_game_project.py tests/test_cli_game_project.py`

---

### Task 5: Documentation and full regression verification

**Files:**
- Create: `docs/phase7d-container-intelligence.md`
- Modify: `README.md`

- [ ] **Step 1: Document behavior and boundaries**

Explain candidate fingerprints/families, custom parser API, safe entry extraction, reports, and the deliberate absence of speculative built-in proprietary parsers.

- [ ] **Step 2: Run the complete suite**

Run: `PYTHONPATH=src python -m pytest -q`

Expected: all Phase 7A–7D tests pass with only the pre-existing optional skip.

- [ ] **Step 3: Review diff for scope/licensing/security**

Confirm no GPL PPSSPP implementation code or commercial game data was copied; confirm no archive extension is treated as proof; confirm all extraction destinations use containment checks.

- [ ] **Step 4: Open PR and verify exact-head CI**

Require successful PR CI on the exact head before merge.

- [ ] **Step 5: Merge exact head and verify `main` CI**

Merge only with `expected_head_sha`, then require successful post-merge `main` CI before declaring Phase 7D complete.
