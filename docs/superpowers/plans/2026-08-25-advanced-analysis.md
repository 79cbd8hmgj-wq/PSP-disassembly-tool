# Phase 6A Advanced Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add jump-table metadata, a normalized call graph, explainable function-confidence scoring, and project-level advanced-analysis reports.

**Architecture:** Extend the spimdisasm adapter only where upstream facts must be captured, then perform higher-level analysis in a pure-Python `advanced.py` layer. Preserve Phase 1–5 serialized metadata and command behavior.

**Tech Stack:** Python 3.10+, dataclasses, pytest, spimdisasm/Rabbitizer optional analysis dependencies.

**Spec:** `docs/superpowers/specs/2026-08-25-advanced-analysis-design.md`

## Global Constraints

- Do not merge or copy upstream engines into the core package.
- Do not infer jump-table targets without spimdisasm's accepted jump-table signal.
- Confidence scores must be deterministic, clamped to `0.0..1.0`, and explainable.
- Existing Phase 1–5 behavior and metadata files must remain compatible.

---

### Task 1: Advanced-analysis data model and pure analyzer

**Files:**
- Modify: `src/pspdisasm/model.py`
- Create: `src/pspdisasm/advanced.py`
- Test: `tests/test_advanced.py`

**Interfaces:**
- Consumes: `ExecutableModel`, `DisassemblyResult`
- Produces: `analyze_advanced(model, disassembly) -> AdvancedAnalysisResult`

- [ ] Write failing tests for direct call-graph edges and confidence scoring.
- [ ] Run focused tests and verify failure because the Phase 6A API does not exist.
- [ ] Add normalized dataclasses and the minimal pure analyzer.
- [ ] Run focused tests and verify green.

### Task 2: Jump tables and resolved indirect calls

**Files:**
- Modify: `src/pspdisasm/model.py`
- Modify: `src/pspdisasm/engines/spim.py`
- Test: `tests/test_spim_adapter.py`

**Interfaces:**
- Produces `DisassemblyResult.jump_tables` and `ReferenceRecord(kind="indirect_call")`.
- `JumpTableRecord.targets` contains only executable mapped addresses.

- [ ] Add failing synthetic tests for accepted jump-table decoding and resolved indirect calls.
- [ ] Verify focused tests fail for missing behavior.
- [ ] Normalize `referencedJumpTableOffsets` and `indirectFunctionCallIntrOffset` from spimdisasm.
- [ ] Verify focused tests and existing adapter tests pass.

### Task 3: Project metadata emission

**Files:**
- Modify: `src/pspdisasm/project.py`
- Test: `tests/test_project.py`

**Interfaces:**
- Generate `metadata/advanced.json`, `metadata/callgraph.json`, `metadata/jump_tables.json`, and `metadata/function_confidence.json`.

- [ ] Add failing project-generation assertions for all four new files.
- [ ] Verify failure before implementation.
- [ ] Run advanced analysis during project generation and write deterministic JSON.
- [ ] Verify project tests pass.

### Task 4: Public API, version, and documentation

**Files:**
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

**Interfaces:**
- Export `analyze_advanced`.
- Bump package version from `0.5.0` to `0.6.0`.

- [ ] Export the Phase 6A API and update version/docs.
- [ ] Run the complete test suite with analysis dependencies.
- [ ] Confirm no Phase 1–5 regressions.
