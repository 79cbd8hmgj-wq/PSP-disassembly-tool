# PSP Executable Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 1 of `pspdisasm`: PSP ELF/PRX/container parsing, module/NID metadata extraction, relocations, and JSON CLI output.

**Architecture:** A dependency-light Python package parses binary metadata into dataclasses. PSP-specific parsing is layered on top of a bounded ELF32 reader, and CLI serialization consumes only the normalized model.

**Tech Stack:** Python 3.10+, dataclasses, struct, argparse, json, pytest for development tests.

**Spec:** `docs/superpowers/specs/2026-08-25-psp-executable-intelligence-design.md`

## Global Constraints

- Python >= 3.10.
- No mandatory third-party runtime dependencies.
- No GPL code copied into the core.
- All binary reads must be bounds checked.
- Encrypted `~PSP` bodies are detected and reported, not silently treated as decoded ELF.

---

### Task 1: Public model and input detection

**Files:**
- Create: `pyproject.toml`
- Create: `src/pspdisasm/__init__.py`
- Create: `src/pspdisasm/errors.py`
- Create: `src/pspdisasm/model.py`
- Create: `src/pspdisasm/detect.py`
- Test: `tests/test_detect.py`

**Interfaces:**
- Produces: `detect_input(data: bytes) -> InputKind`
- Produces: `ParseError`
- Produces: model dataclasses shared by later tasks.

- [ ] Write tests for ELF, `~PSP`, and unknown detection.
- [ ] Run tests and confirm missing-module/behavior failure.
- [ ] Implement the minimum public types and detector.
- [ ] Run tests and confirm green.

### Task 2: PSP outer container header

**Files:**
- Create: `src/pspdisasm/psp_container.py`
- Test: `tests/test_psp_container.py`

**Interfaces:**
- Consumes: `ParseError`, `PspContainerHeader`.
- Produces: `parse_psp_container_header(data: bytes) -> PspContainerHeader`.

- [ ] Write tests for 0x150-byte header fields and truncation.
- [ ] Run tests and confirm red.
- [ ] Implement bounds-checked little-endian parser.
- [ ] Run tests and confirm green.

### Task 3: ELF32 core

**Files:**
- Create: `src/pspdisasm/elf32.py`
- Test: `tests/test_elf32.py`
- Test utility: `tests/fixtures.py`

**Interfaces:**
- Produces: `parse_elf32(data: bytes) -> ElfImage`.
- Produces: `ElfImage.vaddr_to_offset(address: int) -> int | None`.

- [ ] Build a synthetic MIPS ELF fixture and tests for header/program/section parsing and validation.
- [ ] Run tests and confirm red.
- [ ] Implement ELF32 parser with per-table bounds validation.
- [ ] Run tests and confirm green.

### Task 4: PSP PRX metadata and relocations

**Files:**
- Create: `src/pspdisasm/prx.py`
- Test: `tests/test_prx.py`

**Interfaces:**
- Consumes: `ElfImage`.
- Produces: `analyze_prx(data: bytes, elf: ElfImage) -> tuple[ModuleInfo | None, list[LibraryImport], list[LibraryExport], list[Relocation], list[str]]`.

- [ ] Extend synthetic fixture with `.rodata.sceModuleInfo`, export/import tables, and `SHT_PRXRELOC`.
- [ ] Write tests for module name, GP, NIDs, function/variable addresses, entry-length walking, and relocation records.
- [ ] Run tests and confirm red.
- [ ] Implement module-info lookup, table walkers, and Type-A relocation extraction.
- [ ] Add detection/warning for `PT_PRXRELOC2` without decoding it.
- [ ] Run tests and confirm green.

### Task 5: Analyzer facade and CLI

**Files:**
- Create: `src/pspdisasm/analyzer.py`
- Create: `src/pspdisasm/cli.py`
- Create: `src/pspdisasm/__main__.py`
- Test: `tests/test_analyzer.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces: `analyze_bytes(data: bytes, source_name: str = "<memory>") -> ExecutableModel`.
- Produces: `analyze_file(path: Path) -> ExecutableModel`.

- [ ] Write facade tests for raw PRX and `~PSP` paths.
- [ ] Write CLI JSON-output test.
- [ ] Run tests and confirm red.
- [ ] Implement facade, JSON serialization, human summary, and argparse command.
- [ ] Run full suite and confirm green.

### Task 6: Documentation and packaging validation

**Files:**
- Create: `README.md`
- Create: `LICENSE`

**Interfaces:** none.

- [ ] Document current capabilities, limitations, source roles, and Phase 2 handoff.
- [ ] Run `python -m pspdisasm --help` with `PYTHONPATH=src`.
- [ ] Run full tests.
- [ ] Build wheel/sdist if `python -m build` is available; otherwise validate editable/import execution without adding a runtime dependency.
