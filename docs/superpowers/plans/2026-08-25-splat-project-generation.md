# PSP Splat Project Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `pspdisasm project` to generate a deterministic Splat 0.50.0 PSP decompilation workspace.

**Architecture:** Flatten allocated ELF sections by VRAM, translate sections and Phase 2 symbols into Splat-native configuration, and materialize metadata/assembly artifacts around the generated target image. Keep Splat itself optional; generation must not import Splat internals.

**Tech Stack:** Python 3.10+, PyYAML 6.x, existing Phase 1/2 APIs, supplied Splat 0.50.0 conventions.

**Spec:** `docs/superpowers/specs/2026-08-25-splat-project-generation-design.md`

## Global Constraints
- Preserve Phase 1 and Phase 2 public behavior.
- `platform` is `psp`; endianness is `little`; compiler is `GCC`.
- Use Splat-supported `code`, `asm`, `data`, `rodata`, `bss`, and `bin` segment types.
- Do not import Splat as a runtime dependency.
- Reject encrypted `~PSP` containers.
- Output must be deterministic.

---

### Task 1: Flat image and Splat layout model
- [ ] Add failing tests for VRAM-linear ELF flattening and section mapping.
- [ ] Implement bounded flat-image construction and section layout records.
- [ ] Run focused tests.

### Task 2: Config and symbols rendering
- [ ] Add failing tests for PSP YAML options, subsegments, entry/function/string symbols, and deterministic ordering.
- [ ] Implement Splat config and symbol renderers.
- [ ] Parse generated YAML with PyYAML in tests.

### Task 3: Workspace materialization and CLI
- [ ] Add failing end-to-end and CLI tests.
- [ ] Implement workspace writer and `pspdisasm project INPUT OUTPUT`.
- [ ] Emit target, config, metadata, assembly, and directory skeleton.

### Task 4: Documentation and verification
- [ ] Update README and package metadata.
- [ ] Run full suite with supplied Rabbitizer/spimdisasm sources.
- [ ] Run compileall and CLI smoke tests.
- [ ] Verify clean tree and exact Git tree before GitHub fast-forward.
