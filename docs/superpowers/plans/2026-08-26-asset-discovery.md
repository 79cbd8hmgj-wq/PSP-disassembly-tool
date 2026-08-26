# Phase 6D Asset Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conservative embedded PSP/common asset discovery, exact-reference linking, deterministic metadata/report output, and safe extraction to generated PSP decompilation projects.

**Architecture:** Introduce a pure `asset_discovery.py` analysis layer consuming `ExecutableModel`, `DisassemblyResult`, `DataTypingResult`, and `ElfImage`, with format detectors operating only on bounded non-executable file-backed ELF sections. Integrate the normalized `AssetDiscoveryResult` into `ProjectArtifacts` and `generate_project`, preserving Phase 6C outputs and extracting bytes only for records with a validated in-section size.

**Tech Stack:** Python 3.11+, dataclasses, stdlib `struct`/`csv`/`io`, pytest, existing pspdisasm ELF/disassembly/data-typing layers, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-26-asset-discovery-design.md`

## Global Constraints

- Scan only allocated, file-backed, non-executable ELF sections by default.
- Never scan `SHT_NOBITS`, never read beyond section-backed bytes, and never treat `.text` as an asset source in Phase 6D.
- Emit first-class assets only at confidence `>= 0.90`.
- Physically extract only when `extractable=True`, `size` is known and positive, and the extent is wholly within the source section.
- Link only exact asset-start targets already present in normalized references/typed data; do not invent pointer interpretation rules.
- Keep malformed signature candidates non-fatal and deterministic.
- No ISO/CSO opening, recursive filesystem scanning, format conversion, arbitrary archive guessing, or Splat segment rewriting in Phase 6D.
- Public API: `analyze_assets(model, disassembly, data_typing, elf) -> AssetDiscoveryResult`.
- Package version after implementation: `0.9.0`.

---

### Task 1: Normalized asset models and RED API tests

**Files:**
- Modify: `src/pspdisasm/model.py`
- Test: `tests/test_asset_discovery.py`

**Interfaces:**
- Produces `AssetRecord`, `AssetReferenceRecord`, and `AssetDiscoveryResult` with the exact fields in the Phase 6D spec.
- Later tasks import these records from `pspdisasm.model`.

- [ ] **Step 1: Write failing model tests**

Create `tests/test_asset_discovery.py` beginning with construction/asdict tests equivalent to:

```python
from dataclasses import asdict
from pspdisasm.model import AssetDiscoveryResult, AssetRecord, AssetReferenceRecord


def test_asset_models_are_normalized_dataclasses():
    asset = AssetRecord(
        address=0x08802000,
        file_offset=0x200,
        section=".rodata",
        format="png",
        kind="image",
        size=32,
        confidence=1.0,
        evidence=["png_signature", "png_iend"],
        extractable=True,
        suggested_extension="png",
        metadata={"chunk_count": 2},
    )
    reference = AssetReferenceRecord(
        source_address=0x08800100,
        asset_address=asset.address,
        source_function="func_08800100",
        reference_kind="direct",
        asset_format="png",
        confidence=1.0,
        evidence=["reference_record", "asset_exact_start"],
    )
    result = AssetDiscoveryResult("fixture.elf", [asset], [reference], [])
    assert asdict(result)["assets"][0]["format"] == "png"
    assert asdict(result)["references"][0]["asset_address"] == 0x08802000
```

- [ ] **Step 2: Verify RED**

Run branch CI or `PYTHONPATH=src python -m pytest -q tests/test_asset_discovery.py`. Expected failure: asset model classes cannot be imported.

- [ ] **Step 3: Add the three dataclasses**

Append to `src/pspdisasm/model.py`:

```python
@dataclass(slots=True)
class AssetRecord:
    address: int
    file_offset: int
    section: str
    format: str
    kind: str
    size: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    extractable: bool = False
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AssetReferenceRecord:
    source_address: int
    asset_address: int
    source_function: str | None
    reference_kind: str
    asset_format: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssetDiscoveryResult:
    source_name: str
    assets: list[AssetRecord] = field(default_factory=list)
    references: list[AssetReferenceRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Verify GREEN**

Run `PYTHONPATH=src python -m pytest -q tests/test_asset_discovery.py` and confirm the model test passes.

- [ ] **Step 5: Commit**

Commit test plus model additions as `test: define Phase 6D asset models`.

---

### Task 2: RED detector and scan-domain tests

**Files:**
- Modify: `tests/test_asset_discovery.py`
- Create: `src/pspdisasm/asset_discovery.py`

**Interfaces:**
- Consumes `ExecutableModel`, `DisassemblyResult`, `DataTypingResult`, `ElfImage`.
- Produces `analyze_assets(...) -> AssetDiscoveryResult`.
- Internal detector output is normalized immediately into `AssetRecord`; no detector-specific public types.

- [ ] **Step 1: Add failing fixtures/tests for supported formats and scan bounds**

Use small synthetic ELF sections built with the existing `tests.fixtures.build_allegrex_elf32` pattern or local helper constructors. Add focused tests covering:

```python
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"
RIFF_WAVE = b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfmt " + (4).to_bytes(4, "little") + b"\x01\x00\x01\x00"
VAG = b"VAGp" + (0x20).to_bytes(4, "big") + b"\x00" * 4 + (16).to_bytes(4, "big") + (44100).to_bytes(4, "big") + b"\x00" * 44 + b"\x00" * 16
GIM = b"MIG.00.1PSP" + b"\x00" * 24
PMF = b"PSMF" + b"\x00" * 28
```

Required test behaviors in this task:
- valid bounded PNG detected/extractable;
- truncated PNG never over-read;
- JPEG SOI/EOI detected while invalid SOI-only prefix rejected;
- bounded RIFF/WAVE detected, out-of-section declared RIFF rejected;
- RIFF/WAVE with ATRAC-family codec tag records specialization metadata;
- bounded VAG detected, implausible frequency/size rejected;
- GIM and PSMF signatures produce conservative records;
- unaligned signatures are discoverable;
- executable and `SHT_NOBITS` sections are not scanned;
- overlapping candidates resolve deterministically.

Each test should call `analyze_assets(...)` and assert public `AssetRecord` fields, not private detector functions.

- [ ] **Step 2: Verify RED**

Run `PYTHONPATH=src python -m pytest -q tests/test_asset_discovery.py`. Expected failure: `pspdisasm.asset_discovery` / `analyze_assets` does not exist.

- [ ] **Step 3: Implement bounded asset discovery**

Create `src/pspdisasm/asset_discovery.py` with constants `SHF_ALLOC = 0x2`, `SHF_EXECINSTR = 0x4`, `SHT_NOBITS = 8`, candidate helper routines, and:

```python
def analyze_assets(
    model: ExecutableModel,
    disassembly: DisassemblyResult,
    data_typing: DataTypingResult,
    elf: ElfImage,
) -> AssetDiscoveryResult:
    ...
```

Implementation requirements:
- iterate eligible sections sorted by `(addr, index)`;
- bound the scan view to `raw_data[section.offset:section.offset + section.size]` after verifying the end is inside the ELF;
- identify candidate offsets by signatures at byte granularity;
- validate PNG chunks through bounded `IEND`;
- parse JPEG marker segments and entropy data conservatively until EOI;
- validate RIFF declared extent (`8 + riff_size`) and contained chunks; recognize WAVE and capture `fmt ` codec tag, labeling ATRAC/AT3 when codec tags are in the ATRAC family while retaining RIFF/WAVE structural evidence;
- validate VAG big-endian header fields and payload extent;
- recognize GIM/PSMF only with the minimum stable signature/header checks from the spec, keeping them non-extractable when no safe extent is derivable;
- omit GMO unless a safe stable detector can be justified from repository/source evidence;
- resolve same-start/overlap conflicts by confidence, then extractability, then lexical format order; do not allow weak records to overlap a validated bounded asset;
- sort final assets by `(address, format)`;
- detector exceptions caused by malformed candidates must reject the candidate rather than abort analysis.

- [ ] **Step 4: Verify GREEN**

Run the focused asset suite until all detector/scan-domain tests pass.

- [ ] **Step 5: Commit**

Commit as `feat: add conservative embedded asset detection`.

---

### Task 3: Exact reference linking

**Files:**
- Modify: `tests/test_asset_discovery.py`
- Modify: `src/pspdisasm/asset_discovery.py`

**Interfaces:**
- Consumes `DisassemblyResult.references`, `DataTypingResult.typed_references`, and typed data records with exact `target_address`.
- Produces deduplicated `AssetReferenceRecord` entries sorted by `(asset_address, source_address, reference_kind)`.

- [ ] **Step 1: Add failing reference-link tests**

Add tests constructing one accepted asset and normalized references for:
- direct `ReferenceRecord.target_address == asset.address`;
- `TypedReferenceRecord.target_address == asset.address`;
- a `DataTypeRecord` pointer/table field with exact target address;
- unrelated pointer-looking integer does not link;
- duplicate evidence deduplicates one `(source_address, asset_address, reference_kind)` record with stable merged evidence.

Use explicit source addresses/functions and assert confidence never exceeds the asset confidence or typed evidence confidence.

- [ ] **Step 2: Verify RED**

Run the focused reference tests and confirm they fail because references are empty/missing.

- [ ] **Step 3: Implement exact-start linking**

Add a private linker called by `analyze_assets` after candidate resolution. Build an `assets_by_address` map and only accept exact address equality from existing normalized records. Use reference kinds `direct`, `typed`, and `typed_data`. Merge evidence via `sorted(set(...))`; retain the maximum supported confidence for duplicate keys without exceeding asset confidence.

- [ ] **Step 4: Verify GREEN**

Run `PYTHONPATH=src python -m pytest -q tests/test_asset_discovery.py` and confirm all detector plus linker tests pass.

- [ ] **Step 5: Commit**

Commit as `feat: link assets to normalized references`.

---

### Task 4: RED project-output, extraction, API, and version tests

**Files:**
- Create: `tests/test_project_phase6d.py`
- Modify: `src/pspdisasm/project.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

**Interfaces:**
- `ProjectArtifacts` gains `asset_discovery_json: str` and `asset_discovery: AssetDiscoveryResult`.
- `build_project_artifacts` calls `analyze_assets(model, result, data_typing, elf)` after Phase 6C.
- `generate_project` writes Phase 6D metadata/report files and safe asset bytes.

- [ ] **Step 1: Add failing project/API tests**

Create `tests/test_project_phase6d.py` asserting generated projects contain:

```python
expected = {
    "metadata/asset_discovery.json",
    "metadata/assets.json",
    "metadata/asset_references.json",
    "reports/assets.csv",
}
```

Assert:
- full result JSON contains the same asset/reference rows as split files;
- CSV header includes `address,file_offset,section,format,kind,size,confidence,extractable,reference_count,suggested_extension` and rows sort by address/format;
- safely bounded embedded assets produce `assets/<ADDRESS>_<format>.<ext>` containing exactly the validated source bytes;
- recognized unbounded assets do not produce carved files;
- `callable(pspdisasm.analyze_assets)`;
- `pspdisasm.__version__ == "0.9.0"`.

- [ ] **Step 2: Verify RED**

Run `PYTHONPATH=src python -m pytest -q tests/test_project_phase6d.py`. Expected failure: Phase 6D artifact fields/files/API do not exist and version remains `0.8.0`.

- [ ] **Step 3: Integrate asset analysis into project generation**

Modify `project.py` imports and `ProjectArtifacts`, call `analyze_assets` after `analyze_data_types`, serialize complete/split outputs, generate CSV with stdlib `csv`, and copy only validated source byte ranges from `ElfImage.raw_data` according to each `AssetRecord.file_offset/size`. Before extraction re-check `size > 0`, `file_offset >= 0`, and `file_offset + size <= len(raw_data)`; skip any record failing those conditions.

Use deterministic extraction names:

```python
filename = f"{asset.address:08X}_{asset.format}.{asset.suggested_extension}"
```

with a fallback extension of `bin` only when the record is explicitly extractable but no extension is supplied.

- [ ] **Step 4: Export API and bump version**

Modify `src/pspdisasm/__init__.py` to import/export `analyze_assets` and set `__version__ = "0.9.0"`. Update the package version in `pyproject.toml` to `0.9.0` and update README status/output documentation with Phase 6D metadata/report files and the conservative extraction rule.

- [ ] **Step 5: Verify GREEN**

Run the Phase 6D project tests and the existing Phase 6C project tests. Update the Phase 6C version assertion from `0.8.0` to a non-stale compatibility assertion only if needed, without weakening its API checks.

- [ ] **Step 6: Commit**

Commit as `feat: integrate Phase 6D asset intelligence into projects`.

---

### Task 5: Full regression and requirement audit

**Files:**
- Modify only files required by failures revealed during verification.

**Interfaces:**
- No new public interfaces; this task proves Phase 1–6D compatibility.

- [ ] **Step 1: Run focused Phase 6D suite**

Run:

```bash
PYTHONPATH=src python -m pytest -q tests/test_asset_discovery.py tests/test_project_phase6d.py
```

Require zero failures.

- [ ] **Step 2: Run complete regression suite**

Run:

```bash
PYTHONPATH=src python -m pytest -q
```

Require zero failures other than intentionally skipped tests already accepted by the repository.

- [ ] **Step 3: Audit spec coverage**

Check the 26 required cases in `docs/superpowers/specs/2026-08-26-asset-discovery-design.md` against test names/results. Confirm no detector scans executable or NOBITS sections, no uncertain-size candidate is extracted, output ordering is deterministic, and reference linking is exact-start only.

- [ ] **Step 4: Inspect branch diff**

Compare `main...phase6d-asset-discovery`; verify only the spec/plan, asset analysis/models/tests, project integration, API/version, and documentation changed.

- [ ] **Step 5: Integration workflow**

After fresh verification succeeds: create the Phase 6D PR against `main`, verify PR mergeability/CI, merge it, then verify the post-merge `main` Actions run before moving to the next roadmap phase.
