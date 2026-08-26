# Phase 6C Data Typing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved Phase 6C conservative data-typing and reference-intelligence layer and integrate it into generated PSP decompilation projects.

**Architecture:** Add normalized output records to `model.py` and a pure `pspdisasm.data_typing` analysis module that consumes `ExecutableModel`, `DisassemblyResult`, and `ElfImage`. Keep low-level parser/disassembler records immutable, then serialize Phase 6C results separately from existing metadata and allow only high-confidence inferred objects to contribute fallback generated symbols.

**Tech Stack:** Python 3.10+, dataclasses, existing ELF/PSP models, pytest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-25-data-typing-design.md`

## Global Constraints

- Do not import spimdisasm or Rabbitizer from `pspdisasm.data_typing`.
- Do not mutate `ExecutableModel`, `DisassemblyResult`, or Phase 6B NID-link records.
- Never accept a mapped-looking 32-bit integer as a pointer without required corroboration.
- Treat only allocated, file-backed, non-executable sections as data-storage scan regions.
- Never read `SHT_NOBITS` bytes.
- Do not decode or apply `PT_PRXRELOC2` in Phase 6C.
- Preserve deterministic analysis and output ordering.
- Package/API version after completion: `0.8.0`.

---

### Task 1: Normalize Phase 6C records

**Files:**
- Modify: `src/pspdisasm/model.py`
- Test: `tests/test_data_typing.py`

**Interfaces:**
- Produces: `TypedFieldRecord`, `DataTypeRecord`, `TypedReferenceRecord`, `TypedCallEdge`, `DataTypingResult`.

- [ ] Write failing tests that import and instantiate all five normalized record types.
- [ ] Run the Phase 6C tests and confirm they fail because the records do not yet exist.
- [ ] Add the five dataclasses with the exact fields and optional semantics from the approved design.
- [ ] Re-run the record tests and confirm they pass.

### Task 2: Implement exact leaf and table inference

**Files:**
- Create: `src/pspdisasm/data_typing.py`
- Test: `tests/test_data_typing.py`

**Interfaces:**
- Consumes: `ExecutableModel`, `DisassemblyResult`, `ElfImage`.
- Produces: `analyze_data_types(model, disassembly, elf) -> DataTypingResult`.

- [ ] Add failing tests for seeded strings/jump tables, safe relocation evidence, function pointers, ordinary data pointers, unaligned rejection, arbitrary mapped-looking integer rejection, 2/3-entry pointer-table admission rules, homogeneous function-pointer tables, boundary truncation, and table-child suppression.
- [ ] Run those tests and verify expected RED failures.
- [ ] Implement safe ELF section/word mapping, relocation-slot normalization, anchor construction, leaf inference, table-run scanning, deterministic confidence/evidence, and warnings.
- [ ] Re-run the focused tests until GREEN.

### Task 3: Add structural candidates and typed reference intelligence

**Files:**
- Modify: `src/pspdisasm/data_typing.py`
- Test: `tests/test_data_typing.py`

**Interfaces:**
- Produces: `struct_candidate`, `array_candidate`, one-for-one typed references, and additive `typed_indirect` call edges.

- [ ] Add failing tests for struct admission, repeated struct signatures, composite precedence, overlap suppression, typed-reference identity preservation, and typed-indirect call enrichment.
- [ ] Verify RED.
- [ ] Implement bounded 64-byte struct probing, deterministic array-size trials, conflict/overlap resolution, target-type annotation, and indirect-call resolution through accepted function-pointer slots.
- [ ] Re-run the focused tests until GREEN.

### Task 4: Integrate Phase 6C into project generation

**Files:**
- Modify: `src/pspdisasm/project.py`
- Modify: `tests/test_project.py`

**Interfaces:**
- `ProjectArtifacts` gains a `data_typing` result and JSON serialization.
- Generated projects gain `metadata/data_typing.json`, `metadata/data_types.json`, `metadata/typed_references.json`, and `metadata/typed_callgraph.json`.

- [ ] Add failing project-generation tests for all four metadata files and strong inferred-object symbol propagation.
- [ ] Verify RED.
- [ ] Run `analyze_data_types` after Phase 6A/optional Phase 6B analysis, deduplicate typed-indirect edges against identical Phase 6A indirect edges, and serialize all Phase 6C outputs.
- [ ] Extend symbol rendering with only >=0.90-confidence `FUNCPTR_`, `PTR_`, `FUNCPTRTBL_`, and `PTRTBL_` fallbacks while preserving entry/string/curated/function/NID precedence.
- [ ] Re-run project tests until GREEN.

### Task 5: Public API, version, documentation, regression

**Files:**
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`
- Test: `tests/test_data_typing.py`

**Interfaces:**
- Export: `pspdisasm.analyze_data_types`.
- Version: `0.8.0`.

- [ ] Add failing tests for the public export and version.
- [ ] Verify RED.
- [ ] Export the API and bump both version declarations to `0.8.0`.
- [ ] Document Phase 6C outputs and conservative inference boundaries in README.
- [ ] Run `PYTHONPATH=src python -m pytest -q` and confirm the complete Phase 1-6C suite is GREEN.
- [ ] Review the implementation against all 24 required coverage items in the approved spec before merging.
