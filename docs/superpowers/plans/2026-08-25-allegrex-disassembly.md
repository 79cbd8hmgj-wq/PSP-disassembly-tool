# Allegrex Disassembly and Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add PSP Allegrex/VFPU disassembly and normalized function/symbol/reference discovery using the supplied spimdisasm/Rabbitizer engines.

**Architecture:** Keep Phase 1 parsing independent of engine imports. A lazy `SpimdisasmAdapter` translates `ElfImage` code sections into spimdisasm `SectionText` analysis configured for `R4000ALLEGREX`, then converts engine objects into stable `pspdisasm` dataclasses and deterministic CLI/JSON/assembly outputs.

**Tech Stack:** Python 3.10+, spimdisasm 1.42.x, Rabbitizer 1.16.x, argparse, dataclasses, pytest.

**Spec:** `docs/superpowers/specs/2026-08-25-allegrex-disassembly-design.md`

## Global Constraints

- Preserve every Phase 1 test and public parser behavior.
- Keep spimdisasm/Rabbitizer imports lazy so `pspdisasm analyze` works without the optional analysis engines.
- Use `rabbitizer.InstrCategory.R4000ALLEGREX` for every executable section.
- Do not copy upstream implementation code into this project.
- Keep m2c out-of-process and out of Phase 2.
- Refuse encrypted `~PSP` bodies for instruction analysis.
- Sort and deduplicate public records for deterministic JSON.

---

### Task 1: Phase 2 public model and optional-engine boundary

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/pspdisasm/errors.py`
- Modify: `src/pspdisasm/model.py`
- Create: `src/pspdisasm/engines/__init__.py`
- Create: `src/pspdisasm/engines/spim.py`
- Test: `tests/test_engine_boundary.py`

**Interfaces:**
- Produces: `EngineUnavailableError`
- Produces: `DisassemblyError`
- Produces: `EngineInfo`, `FunctionRecord`, `SymbolRecord`, `ReferenceRecord`, `StringRecord`, `AssemblySection`, `DisassemblyResult`
- Produces: `load_engines() -> EngineModules`

- [x] Write a failing test that blocks imports of `spimdisasm`/`rabbitizer`, imports Phase 1 normally, then asserts `load_engines()` raises `EngineUnavailableError` with `pspdisasm[analysis]` guidance.
- [x] Run `PYTHONPATH=src pytest tests/test_engine_boundary.py -q` and confirm red because the engine boundary does not exist.
- [x] Add the model/error types, `[project.optional-dependencies].analysis = ["spimdisasm>=1.42.4,<2"]`, and lazy loader.
- [x] Re-run the focused test and confirm green.
- [x] Run all existing tests and confirm Phase 1 remains green.

### Task 2: Synthetic executable-code fixture and Allegrex decoding adapter

**Files:**
- Modify: `tests/fixtures.py`
- Create: `tests/test_spim_adapter.py`
- Modify: `src/pspdisasm/engines/spim.py`

**Interfaces:**
- Produces: `SpimdisasmAdapter.analyze(elf: ElfImage, model: ExecutableModel) -> DisassemblyResult`

- [x] Add a synthetic ELF fixture whose `.text` contains `clz`, `vzero.s`, `jr $ra`, and delay-slot `nop` words.
- [x] Write failing tests asserting Rabbitizer renders `clz` and `vzero.s` and spimdisasm discovers a function at the section start.
- [x] Run the focused tests and confirm red.
- [x] Create a spimdisasm `Context`, set its global ranges, instantiate `SectionText` from exact section bytes, set `instrCat = R4000ALLEGREX`, call `analyze()`, and normalize functions/assembly sections.
- [x] Re-run focused tests and confirm green.

### Task 3: Calls, branches, symbols, and pointer references

**Files:**
- Modify: `tests/fixtures.py`
- Modify: `tests/test_spim_adapter.py`
- Modify: `src/pspdisasm/engines/spim.py`

**Interfaces:**
- Produces deterministic `ReferenceRecord` values with `kind` in `{"call", "branch", "data", "pointer"}`.
- Produces deterministic `SymbolRecord` values from discovered context symbols and known Phase 1 seeds.

- [x] Extend the fixture with two functions, a direct `jal`, a conditional branch, and a LUI/addiu address materialization into `.rodata`.
- [x] Write failing assertions for call target, branch target, source function, mapped target section, and data/pointer target.
- [x] Run focused tests and confirm red.
- [x] Translate `SymbolFunction.instrAnalyzer.funcCallInstrOffsets`, `branchInstrOffsets`, `symbolInstrOffset`, and `referencedVrams`; deduplicate on source/target/kind.
- [x] Seed the context with the ELF entrypoint and mapped PSP import/export addresses before analysis.
- [x] Normalize discovered context symbols without exposing spimdisasm classes.
- [x] Re-run focused tests and confirm green.

### Task 4: Conservative referenced-string detection

**Files:**
- Modify: `tests/fixtures.py`
- Modify: `tests/test_spim_adapter.py`
- Modify: `src/pspdisasm/engines/spim.py`

**Interfaces:**
- Produces: `StringRecord(address, value, section, referenced_by)`.

- [x] Put `b"Hello PSP!\\0"` in referenced `.rodata` and write a failing test that expects one string record linked to the referencing instruction.
- [x] Run the focused test and confirm red.
- [x] Resolve target address to file offset, require a mapped non-executable section, printable ASCII/UTF-8 bytes, a terminating NUL, and minimum length 4 before recording a string.
- [x] Sort/deduplicate `referenced_by` addresses and string records.
- [x] Re-run focused tests and confirm green.

### Task 5: Disassembly facade and CLI

**Files:**
- Create: `src/pspdisasm/disassembler.py`
- Modify: `src/pspdisasm/cli.py`
- Modify: `src/pspdisasm/__init__.py`
- Create: `tests/test_disassembler.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Produces: `disassemble_bytes(data: bytes, source_name: str = "<memory>") -> DisassemblyResult`
- Produces: `disassemble_file(path: Path | str) -> DisassemblyResult`
- Adds: `pspdisasm disasm INPUT [--json OUTPUT] [--asm-dir DIR]`

- [x] Write failing facade tests for raw ELF/PRX and encrypted `~PSP` rejection.
- [x] Write failing CLI tests for JSON output and deterministic `.s` output under `--asm-dir`.
- [x] Run focused tests and confirm red.
- [x] Implement facade by reusing `detect_input`, `parse_elf32`, and `analyze_bytes`; never reimplement Phase 1 parsing.
- [x] Implement CLI subcommand, JSON serialization, human summary, and sanitized assembly-section filenames.
- [x] Re-run focused tests and confirm green.

### Task 6: Documentation, engine installation, and full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-25-allegrex-disassembly.md`

**Interfaces:** none.

- [x] Document `pip install -e '.[analysis]'`, local supplied-source installation, `disasm` usage, current outputs, and Phase 3 handoff.
- [x] Run `PYTHONPATH=src pytest -q` and require zero failures.
- [x] Run `PYTHONPATH=src python -m compileall -q src tests` and require exit 0.
- [x] Run CLI `--help`, `analyze`, and `disasm` smoke tests on synthetic fixtures.
- [x] Mark completed plan checkboxes, inspect `git diff --check`, and commit the verified Phase 2 tree.
