# Phase 5 asm-differ Matching Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add single-function original-vs-recompiled matching through external asm-differ with deterministic PSP reference objects and persistent normalized reports.

**Architecture:** Add a focused `matcher.py` subsystem. It reads Phase 3 function metadata, synthesizes an ELF32 MIPS reference object from Phase 2 instruction words, optionally executes an explicit build command, invokes asm-differ in JSON object mode, normalizes scores/rows, and writes atomic metadata/reports. The CLI only orchestrates this public API.

**Tech Stack:** Python 3.10+, stdlib subprocess/json/struct/tomllib/shlex/tempfile, external asm-differ, external MIPS-capable objdump.

**Spec:** `docs/superpowers/specs/2026-08-25-asm-differ-matching-design.md`

## Global Constraints

- Keep asm-differ out-of-process and out of mandatory/optional Python dependencies.
- Do not invent or bundle a PSP compiler.
- Run caller build commands without `shell=True`.
- Default section is `.text`; default asm-differ algorithm is `difflib`.
- Preserve prior successful reports on build/backend failure.
- Auto-generated reference ELF is little-endian `ET_REL`/`EM_MIPS`.

---

### Task 1: Matching metadata and reference object

**Files:**
- Create: `src/pspdisasm/matcher.py`
- Test: `tests/test_matcher.py`

**Interfaces:**
- Produces `resolve_match_function(project_dir, selector)` and `build_reference_object(function)`.

- [ ] Write failing tests for name/address lookup and emitted ELF/symbol table.
- [ ] Run focused tests and verify missing implementation failure.
- [ ] Implement strict metadata parsing and minimal ELF32 MIPS object generation.
- [ ] Run focused tests and verify pass.

### Task 2: External tool and build orchestration

**Files:**
- Modify: `src/pspdisasm/matcher.py`
- Modify: `src/pspdisasm/errors.py`
- Test: `tests/test_matcher.py`

**Interfaces:**
- Produces `resolve_asm_differ_command`, `resolve_objdump`, and typed matching errors.

- [ ] Write failing tests for path resolution, Python script execution, argv build execution, and failure preservation.
- [ ] Run focused tests and verify intended failures.
- [ ] Implement explicit/env/PATH resolution and shell-free subprocess execution.
- [ ] Run focused tests and verify pass.

### Task 3: JSON matching and persistence

**Files:**
- Modify: `src/pspdisasm/matcher.py`
- Test: `tests/test_matcher.py`

**Interfaces:**
- Produces `match_project_function(...) -> MatchResult`.

- [ ] Write failing tests using a fake asm-differ JSON backend for exact and mismatched results.
- [ ] Verify tests fail for missing workflow.
- [ ] Implement temporary diff settings, asm-differ invocation, JSON validation, row classification, similarity calculation, and atomic report writes.
- [ ] Verify focused tests pass.

### Task 4: Public CLI and documentation

**Files:**
- Modify: `src/pspdisasm/cli.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`
- Test: `tests/test_matcher.py`

**Interfaces:**
- Adds `pspdisasm match` command and bumps package version to `0.5.0`.

- [ ] Add parser expectations for match command/options.
- [ ] Implement CLI call, summary output, and matching exception handling.
- [ ] Document workflow, compiler/toolchain requirement, artifacts, and relocation limitation.
- [ ] Run bytecode compilation and all locally available regression/focused tests.

### Task 5: Supplied asm-differ integration probe and GitHub handoff

**Files:** No production files beyond prior tasks.

- [ ] Run the supplied asm-differ source against synthesized identical MIPS objects and verify zero score.
- [ ] Run it against a changed MIPS object and verify nonzero score.
- [ ] Verify final local files compile and focused tests pass.
- [ ] Confirm remote `main` remains at Phase 4.
- [ ] Assemble GitHub tree on top of Phase 4 and require exact expected tree content before non-force fast-forward.
