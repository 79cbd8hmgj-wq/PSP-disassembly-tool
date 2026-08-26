# Phase 7C Game Resource Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `game-project` so ISO/CSO inputs produce deterministic whole-disc resource extraction, known-format classification, conservative embedded-resource discovery, and resource reports while preserving unknown proprietary files.

**Architecture:** Move Phase 6D byte-signature logic into a neutral `resource_formats.py` detector layer, adapt Phase 6D back onto that layer, add safe resource extraction primitives to the disc layer, and add a dedicated `game_resources.py` orchestrator/report model. `generate_game_project()` invokes resource analysis after disc intake/module processing and exposes counters through the existing CLI/API.

**Tech Stack:** Python 3.10+, dataclasses, pathlib, csv/json, pycdlib optional disc backend, existing PSP ISO/CSO reader and Phase 6D analysis models.

**Spec:** `docs/superpowers/specs/2026-08-26-game-resource-orchestration-design.md`

## Global Constraints

- Do not copy GPL PPSSPP implementation code into the MIT core; use it only as a behavioral/format reference.
- Do not claim universal support for proprietary `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, or `.PKG` formats.
- Unknown files must remain represented as unknown rather than guessed.
- Traversal/symlink containment violations are fatal game-level integrity errors.
- Malformed or unsupported resource files are non-fatal and recorded as warnings.
- Keep `pspdisasm game` scan-only; Phase 7C runs automatically only through `game-project`/`generate_game_project()`.
- Normalized metadata must be deterministic and must not contain environment-dependent absolute output paths.

---

### Task 1: Shared resource-format detector layer

**Files:**
- Create: `src/pspdisasm/resource_formats.py`
- Modify: `src/pspdisasm/asset_discovery.py`
- Create: `tests/test_resource_formats.py`
- Modify: `tests/test_asset_discovery.py`

**Interfaces:**
- Produces: `ResourceFormatMatch`, `detect_resource_at(data: bytes, offset: int = 0) -> ResourceFormatMatch | None`, `scan_resource_bytes(data: bytes, *, minimum_confidence: float = 0.90) -> list[ResourceFormatMatch]`.
- `asset_discovery.py` consumes these neutral matches and converts them into existing `AssetRecord` values with section-relative addresses/file offsets.

- [ ] **Step 1: Write failing detector parity tests**

Add synthetic PNG, JPEG, RIFF/WAVE, AT3, VAG, GIM and PSMF/PMF byte samples to `tests/test_resource_formats.py` and assert neutral matches preserve the Phase 6D fields:

```python
match = detect_resource_at(png_bytes)
assert match is not None
assert match.format == "png"
assert match.kind == "image"
assert match.offset == 0
assert match.size == len(png_bytes)
assert match.extractable is True
assert match.confidence == 1.0
```

Add a scan test with junk prefix + PNG + junk suffix and assert the record offset is exact.

- [ ] **Step 2: Run the new tests and confirm RED**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_resource_formats.py -q
```

Expected: import failure because `pspdisasm.resource_formats` does not exist.

- [ ] **Step 3: Implement the neutral format model and detectors**

Create:

```python
@dataclass(slots=True)
class ResourceFormatMatch:
    offset: int
    format: str
    kind: str
    size: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    extractable: bool = False
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
```

Move the existing format parsing rules from `asset_discovery.py` into functions that use byte offsets only. `scan_resource_bytes()` must scan byte-by-byte, accept confidence >= 0.90, prefer higher-confidence/bounded candidates at the same offset, and advance by a proven bounded size when possible.

- [ ] **Step 4: Adapt Phase 6D to shared matches**

Replace `_DETECTORS` and `_scan_section()` format logic with `scan_resource_bytes(data)` and convert each match using:

```python
AssetRecord(
    address=section.addr + match.offset,
    file_offset=section.offset + match.offset,
    section=section.name,
    format=match.format,
    kind=match.kind,
    size=match.size,
    confidence=match.confidence,
    evidence=list(match.evidence),
    extractable=match.extractable,
    suggested_extension=match.suggested_extension,
    metadata=dict(match.metadata),
)
```

Do not change Phase 6D linking semantics.

- [ ] **Step 5: Run detector and Phase 6D regression tests**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_resource_formats.py tests/test_asset_discovery.py -q
PYTHONPATH=src python -m pytest -q
```

Expected: all existing tests remain green.

- [ ] **Step 6: Commit**

```bash
git add src/pspdisasm/resource_formats.py src/pspdisasm/asset_discovery.py tests/test_resource_formats.py tests/test_asset_discovery.py
git commit -m "refactor: share PSP resource format detectors"
```

---

### Task 2: Safe disc-resource extraction boundary

**Files:**
- Modify: `src/pspdisasm/disc.py`
- Modify: `tests/test_disc.py`

**Interfaces:**
- Produces: `extract_disc_resources(path: Path | str, output_dir: Path | str, *, manifest: GameDiscManifest | None = None) -> list[DiscResourceRecord]`.
- Produces dataclass `DiscResourceRecord(path: str, size: int, output_path: str)`.
- Consumes existing `GameDiscManifest.files` and extracts only records whose classification is `resource`.

- [ ] **Step 1: Write failing resource extraction tests**

Build a synthetic ISO containing a valid EBOOT plus:

```text
PSP_GAME/USRDIR/TEXTURE.PNG
PSP_GAME/USRDIR/DATA.BIN
```

Call `extract_disc_resources()` and assert deterministic records and files beneath:

```text
resources/files/PSP_GAME/USRDIR/TEXTURE.PNG
resources/files/PSP_GAME/USRDIR/DATA.BIN
```

Add a containment regression by monkeypatching a manifest resource path containing `../escape` and assert `ParseError("Unsafe disc extraction path")`.

- [ ] **Step 2: Run the focused tests and confirm RED**

```bash
PYTHONPATH=src python -m pytest tests/test_disc.py -q
```

Expected: missing `extract_disc_resources`/`DiscResourceRecord`.

- [ ] **Step 3: Implement extraction without changing `scan_game_disc()` semantics**

`extract_disc_resources()` reopens the ISO/CSO through `open_disc_stream()`, walks the filesystem, maps logical path -> physical ISO path, validates every destination through `_safe_target()`, and copies only manifest records classified `resource`.

Return paths relative to the Phase 7 output root, for example:

```python
DiscResourceRecord(
    path=item.path,
    size=item.size,
    output_path="resources/files/PSP_GAME/USRDIR/TEXTURE.PNG",
)
```

Do not make `scan_game_disc()` copy resource files; the lightweight `game` command must remain unchanged.

- [ ] **Step 4: Run disc and full regressions**

```bash
PYTHONPATH=src python -m pytest tests/test_disc.py tests/test_cli_game.py -q
PYTHONPATH=src python -m pytest -q
```

- [ ] **Step 5: Commit**

```bash
git add src/pspdisasm/disc.py tests/test_disc.py
git commit -m "feat: extract PSP disc resources safely"
```

---

### Task 3: Game-resource scanner, unknown preservation, embedded discovery, and reports

**Files:**
- Create: `src/pspdisasm/game_resources.py`
- Create: `tests/test_game_resources.py`

**Interfaces:**
- Consumes: `DiscResourceRecord` from Task 2 and shared `resource_formats` detectors from Task 1.
- Produces: `GameResourceRecord`, `EmbeddedGameResourceRecord`, `GameResourceAnalysis`, `ResourceContainerParser` protocol, `analyze_game_resources(source_name: str, output_dir: Path | str, resources: Iterable[DiscResourceRecord]) -> GameResourceAnalysis`.
- Writes: `metadata/game_resources.json`, `metadata/embedded_resources.json`, `reports/game_resources.csv`, bounded embedded extractions beneath `resources/embedded/`.

- [ ] **Step 1: Write failing loose-file classification tests**

Create extracted synthetic resource files and assert:

```python
analysis = analyze_game_resources("game.iso", output, records)
known = next(r for r in analysis.resources if r.path.endswith("TEXTURE.PNG"))
assert known.detected_format == "png"
assert known.kind == "image"
assert known.confidence == 1.0

unknown = next(r for r in analysis.resources if r.path.endswith("DATA.BIN"))
assert unknown.detected_format == "unknown"
assert unknown.kind == "unknown"
```

Assert records stay sorted by logical path and output paths are relative.

- [ ] **Step 2: Write failing embedded-resource tests**

Create a loose `DATA.BIN` containing junk + valid PNG + junk. Assert one embedded record with the exact parent path and byte offset, and assert a bounded extraction is written below:

```text
resources/embedded/PSP_GAME/USRDIR/DATA.BIN/<OFFSET>_png.png
```

- [ ] **Step 3: Write failing oversized/malformed isolation tests**

Define `MAX_EMBEDDED_SCAN_BYTES = 64 * 1024 * 1024`. Monkeypatch it small in tests, create a larger file, and assert:

- file remains inventoried;
- no embedded scan is performed;
- warning states embedded scanning was skipped due to size.

Also create malformed RIFF-like bytes and assert the file remains `unknown` without aborting the analysis.

- [ ] **Step 4: Implement models and classification**

Use dedicated dataclasses. For a loose file, call `detect_resource_at(prefix_or_data, 0)`. A match is authoritative for the file only when its offset is zero and confidence >= 0.90. Otherwise preserve `unknown`.

For files <= `MAX_EMBEDDED_SCAN_BYTES`, read bytes and call `scan_resource_bytes()`. Exclude a single match that exactly represents the entire loose file from the embedded list so a PNG file is not redundantly reported as an embedded PNG inside itself.

- [ ] **Step 5: Implement bounded embedded extraction**

For a match with `extractable=True`, known positive size, and in-bounds extent, write exactly those bytes under a containment-checked `resources/embedded/` path. Use an offset formatted as eight uppercase hex digits.

- [ ] **Step 6: Implement deterministic reports**

Write `metadata/game_resources.json` from `asdict(GameResourceAnalysis)`, `metadata/embedded_resources.json` from the embedded list, and CSV columns:

```text
path,size,detected_format,kind,confidence,embedded_count,extracted_path,evidence
```

Use sorted JSON keys and stable resource ordering.

- [ ] **Step 7: Add the empty parser registry boundary**

Define the `ResourceContainerParser` protocol and an internal empty registry tuple. Do not ship speculative proprietary parsers in this task.

- [ ] **Step 8: Run focused and full tests**

```bash
PYTHONPATH=src python -m pytest tests/test_game_resources.py -q
PYTHONPATH=src python -m pytest -q
```

- [ ] **Step 9: Commit**

```bash
git add src/pspdisasm/game_resources.py tests/test_game_resources.py
git commit -m "feat: analyze whole-game PSP resources"
```

---

### Task 4: Integrate Phase 7C into game-project API/CLI and documentation

**Files:**
- Modify: `src/pspdisasm/game_project.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `src/pspdisasm/cli.py`
- Modify: `tests/test_game_project.py`
- Modify: `tests/test_cli_game_project.py`
- Modify: `README.md`
- Create: `docs/phase7c-game-resources.md`

**Interfaces:**
- `generate_game_project()` calls `extract_disc_resources()` then `analyze_game_resources()`.
- Extend `GameProjectResult` with `resource_count`, `known_resource_count`, `unknown_resource_count`, `embedded_resource_count`, `resources_path`.
- Publicly export `analyze_game_resources` and its result/record types only if the project’s existing API style supports record exports; always export `analyze_game_resources`.

- [ ] **Step 1: Write failing game-project integration tests**

Extend the synthetic ISO helper to include PNG and unknown resources. Assert `generate_game_project()` still analyzes the boot module and now returns:

```python
assert result.resource_count == 2
assert result.known_resource_count == 1
assert result.unknown_resource_count == 1
assert result.resources_path == output / "metadata" / "game_resources.json"
```

Assert `metadata/game_resources.json` and `reports/game_resources.csv` exist.

- [ ] **Step 2: Write failing CLI summary test**

Run:

```python
code = main(["game-project", str(image), str(output)])
```

and assert stdout includes:

```text
Resources: 2
Known resources: 1
Unknown resources: 1
Embedded resources: 0
```

Also retain the existing `game` test to prove scan-only behavior did not change.

- [ ] **Step 3: Implement orchestration and result counters**

After `scan_game_disc()` and before final metadata return:

```python
resource_files = extract_disc_resources(source_path, output, manifest=manifest)
resource_analysis = analyze_game_resources(str(source_path), output, resource_files)
```

Derive counters from the analysis records. Resource-local warnings remain in resource metadata; containment errors propagate.

- [ ] **Step 4: Wire CLI/public API**

Add the four Phase 7C counters to only the `game-project` summary. Export `analyze_game_resources` from `pspdisasm.__init__`.

- [ ] **Step 5: Update README and Phase 7C documentation**

Document:

- Phase 7C current status;
- automatic whole-disc resource extraction/classification;
- supported loose/embedded formats;
- unknown proprietary archive preservation;
- report/output tree;
- 64 MiB embedded-scan safety ceiling;
- plugin boundary for future real-game archive parsers;
- remaining limitations (no universal archive parser, no asset transcoding, no PSP crypto).

- [ ] **Step 6: Run focused tests**

```bash
PYTHONPATH=src python -m pytest tests/test_game_project.py tests/test_cli_game_project.py -q
```

- [ ] **Step 7: Run full verification**

```bash
python -m pip install -e '.[analysis,disc]' pytest
PYTHONPATH=src python -m pytest -q
```

Expected: all tests pass; only the pre-existing intentional skip remains.

- [ ] **Step 8: Commit**

```bash
git add src/pspdisasm/game_project.py src/pspdisasm/__init__.py src/pspdisasm/cli.py tests/test_game_project.py tests/test_cli_game_project.py README.md docs/phase7c-game-resources.md
git commit -m "feat: integrate Phase 7C game resources"
```

---

### Task 5: Final review, PR verification, and merge

**Files:**
- Review all Phase 7C changed files.

**Interfaces:**
- No new code interface; validates the complete feature against the spec.

- [ ] **Step 1: Compare branch against `main`**

Confirm only Phase 7C design/plan/docs, detector refactor, resource extraction/scanner, integration, and tests changed.

- [ ] **Step 2: Review format safety and containment**

Verify malformed lengths never authorize out-of-bounds reads/extractions, unknown files are not guessed, resource destination paths cannot escape output roots, and module-local/game-level error boundaries remain unchanged.

- [ ] **Step 3: Run fresh full CI on final head**

Require the GitHub workflow for the exact branch head to pass.

- [ ] **Step 4: Open PR against `main`**

PR summary must include supported formats, unknown-container boundary, safety ceiling, output reports, and exact test result.

- [ ] **Step 5: Verify PR merge-ref CI and review state**

Require a green merge-ref workflow and no unresolved review threads/comments before merge.

- [ ] **Step 6: Merge exact verified head**

Use expected head SHA protection.

- [ ] **Step 7: Verify post-merge `main` CI**

Completion requires the workflow on the resulting `main` merge commit to pass.