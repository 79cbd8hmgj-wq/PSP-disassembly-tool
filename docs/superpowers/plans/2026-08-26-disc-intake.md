# Phase 7A Disc Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept PSP ISO/CSO game images and produce a deterministic game manifest plus safely extracted executable candidates for Phase 7B.

**Architecture:** Add a clean-room seekable CISO reader, a small PARAM.SFO parser, and a pycdlib-backed PSP disc scanner. Keep disc dependencies optional and do not alter the existing ELF/PRX analyzer boundary.

**Tech Stack:** Python 3.10+, stdlib `io`/`struct`/`zlib`, optional `pycdlib>=1.14,<2`, optional `lz4>=4.3,<5`, pytest.

**Spec:** `docs/superpowers/specs/2026-08-26-disc-intake-design.md`

## Global Constraints

- The repository remains MIT; PPSSPP code is reference-only and pycdlib source is not copied.
- Raw ISO and CISO v0/v1 must work without `lz4`; CISO v2 LZ4 blocks require the `disc` extra.
- The existing executable-only commands must not import pycdlib or lz4 at startup.
- Whole-image CSO decompression is forbidden; reads are block-addressed and seekable.
- Extraction must never write outside `<output>/modules`.
- Phase 7A stops before per-module disassembly/linking/project generation.

---

### Task 1: Seekable CISO image reader

**Files:**
- Create: `src/pspdisasm/disc_image.py`
- Create: `tests/test_disc_image.py`

**Interfaces:**
- Produces: `DiscImageFormat`, `CsoHeader`, `CsoReader`, `detect_disc_format(data: bytes)`, `open_disc_stream(path)`.

- [ ] **Step 1: Write failing tests**

Create synthetic CISO fixtures containing one raw block and one raw-DEFLATE block. Assert detection, cross-block `read()`, `seek()`, last-block truncation, and rejection of non-monotonic indexes. Add a version-2 LZ4 test guarded by `pytest.importorskip("lz4.block")`.

```python
def test_cso_reader_reads_across_plain_and_deflate_blocks(tmp_path):
    path = tmp_path / "game.cso"
    path.write_bytes(build_cso([b"A" * 2048, b"B" * 2048], compressed={1}))
    with CsoReader(path) as reader:
        reader.seek(2040)
        assert reader.read(16) == b"A" * 8 + b"B" * 8
```

- [ ] **Step 2: Run tests to verify RED**

Run: `PYTHONPATH=src python -m pytest tests/test_disc_image.py -q`

Expected: collection/import failure because `pspdisasm.disc_image` does not exist.

- [ ] **Step 3: Implement minimal reader**

Implement CISO header parsing with `<4sIQIBB2s`, validate index count and offsets, and expose a `io.RawIOBase` reader. For v1, high bit means uncompressed. For v2, spans >= logical block size are uncompressed; smaller blocks use raw DEFLATE unless the high bit selects `lz4.block.decompress`.

- [ ] **Step 4: Verify GREEN**

Run: `PYTHONPATH=src python -m pytest tests/test_disc_image.py -q`

Expected: all Task 1 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pspdisasm/disc_image.py tests/test_disc_image.py
git commit -m "feat: add seekable CISO disc reader"
```

---

### Task 2: PARAM.SFO parser

**Files:**
- Create: `src/pspdisasm/sfo.py`
- Create: `tests/test_sfo.py`

**Interfaces:**
- Produces: `parse_param_sfo(data: bytes) -> dict[str, object]`.

- [ ] **Step 1: Write failing tests**

Construct a PSF fixture with UTF-8 string and uint32 entries. Assert exact values and malformed table rejection.

```python
def test_parse_param_sfo_reads_strings_and_integers():
    values = parse_param_sfo(build_sfo({"TITLE": "Test Game", "MEMSIZE": 1}))
    assert values["TITLE"] == "Test Game"
    assert values["MEMSIZE"] == 1
```

- [ ] **Step 2: Run tests to verify RED**

Run: `PYTHONPATH=src python -m pytest tests/test_sfo.py -q`

Expected: import failure because `pspdisasm.sfo` does not exist.

- [ ] **Step 3: Implement parser**

Validate `\x00PSF`, header/table bounds, 16-byte entry records, key offsets, data offsets, and lengths. Decode format `0x0204` as UTF-8 text with trailing NUL removed and `0x0404` as little-endian uint32. Preserve unsupported formats as raw bytes rather than guessing.

- [ ] **Step 4: Verify GREEN**

Run: `PYTHONPATH=src python -m pytest tests/test_sfo.py -q`

Expected: all Task 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pspdisasm/sfo.py tests/test_sfo.py
git commit -m "feat: parse PSP PARAM.SFO metadata"
```

---

### Task 3: PSP disc manifest and safe executable extraction

**Files:**
- Modify: `src/pspdisasm/model.py`
- Create: `src/pspdisasm/disc.py`
- Create: `tests/test_disc.py`

**Interfaces:**
- Produces model types `DiscFileRecord`, `GameModuleRecord`, `GameDiscManifest`.
- Produces `scan_game_disc(path: Path | str, output_dir: Path | str | None = None) -> GameDiscManifest`.
- Consumes `open_disc_stream()` and `parse_param_sfo()`.

- [ ] **Step 1: Write failing tests**

Use pycdlib to build a tiny ISO containing:

- `/PSP_GAME/PARAM.SFO;1`
- `/PSP_GAME/SYSDIR/EBOOT.BIN;1` with ELF magic
- `/PSP_GAME/USRDIR/PLUGIN.PRX;1` with `~PSP` magic
- `/PSP_GAME/USRDIR/TEXTURE.GIM;1`

Assert `EBOOT.BIN` is selected as boot, `PLUGIN.PRX` is classified as a module, resource paths are normalized without `;1`, manifest ordering is deterministic, and only executable candidates are extracted.

Add a second test where invalid `EBOOT.BIN` falls back to executable `BOOT.BIN`.

- [ ] **Step 2: Run tests to verify RED**

Run: `PYTHONPATH=src python -m pytest tests/test_disc.py -q`

Expected: import failure because `pspdisasm.disc` and manifest model types do not exist.

- [ ] **Step 3: Implement scanner**

Dynamically import pycdlib inside the scanner. Use `open_disc_stream()` with `PyCdlib.open_fp()`, walk ISO paths, preserve physical ISO paths for reads, normalize logical paths, inspect the first four bytes of candidates, parse PARAM.SFO when present, select boot according to the spec, and safely extract boot/module candidates under `modules/`.

Use resolved-path containment checks before every write:

```python
root = (output_dir / "modules").resolve()
target = (root / logical_path).resolve()
if target != root and root not in target.parents:
    raise ParseError(f"Unsafe disc extraction path: {logical_path}")
```

- [ ] **Step 4: Verify GREEN**

Run: `PYTHONPATH=src python -m pytest tests/test_disc.py -q`

Expected: all Task 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pspdisasm/model.py src/pspdisasm/disc.py tests/test_disc.py
git commit -m "feat: scan PSP game discs and extract modules"
```

---

### Task 4: CLI, public API, optional dependencies, CI, and documentation

**Files:**
- Modify: `src/pspdisasm/cli.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `.github/workflows/tests.yml`
- Modify: `tests/test_cli.py`
- Modify: `README.md`

**Interfaces:**
- Adds CLI: `pspdisasm game INPUT OUTPUT`.
- Public API exports: `scan_game_disc`.
- Adds optional extra: `disc = ["pycdlib>=1.14,<2", "lz4>=4.3,<5"]`.

- [ ] **Step 1: Write failing CLI test**

Build a tiny PSP ISO fixture, invoke:

```python
code = main(["game", str(image), str(output)])
```

Assert exit code 0, `metadata/disc.json`, `metadata/param_sfo.json`, and extracted `modules/PSP_GAME/SYSDIR/EBOOT.BIN` exist.

- [ ] **Step 2: Run test to verify RED**

Run: `PYTHONPATH=src python -m pytest tests/test_cli.py -q`

Expected: argparse rejects unknown command `game`.

- [ ] **Step 3: Wire command and dependencies**

Add the parser command, call `scan_game_disc`, emit a concise summary, export the API, add the `disc` extra, and change CI install to:

```yaml
run: python -m pip install -e '.[analysis,disc]' pytest
```

Update README with ISO/CSO usage, Phase 7A scope, optional dependency installation, and encrypted `~PSP` limitation.

- [ ] **Step 4: Run focused and full tests**

Run:

```bash
PYTHONPATH=src python -m pytest tests/test_disc_image.py tests/test_sfo.py tests/test_disc.py tests/test_cli.py -q
PYTHONPATH=src python -m pytest -q
```

Expected: full suite passes with no regressions.

- [ ] **Step 5: Commit**

```bash
git add src/pspdisasm/cli.py src/pspdisasm/__init__.py pyproject.toml .github/workflows/tests.yml tests/test_cli.py README.md
git commit -m "feat: expose whole-disc PSP intake workflow"
```

---

## Self-review

- Spec coverage: CISO reading, ISO traversal, SFO metadata, boot selection, manifest/extraction, dependency isolation, CLI, CI, and docs are each assigned to a task.
- Scope: Phase 7B analysis orchestration is explicitly excluded.
- Type consistency: Task 3 model/function names match Task 4 public API and CLI use.
- No implementation task copies PPSSPP or pycdlib source into the repository.
