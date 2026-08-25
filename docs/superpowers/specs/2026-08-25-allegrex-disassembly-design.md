# Allegrex Disassembly and Discovery Design

## Goal

Build Phase 2 of `pspdisasm`: consume the Phase 1 `ExecutableModel` plus raw ELF/PRX bytes, run PSP Allegrex analysis through the supplied spimdisasm/Rabbitizer engines, and emit assembly plus normalized functions, symbols, calls, branches, pointer references, and string references.

## Architecture

Phase 2 adds a lazy engine adapter. Phase 1 parsing remains usable without third-party dependencies; disassembly commands require the `analysis` optional dependency. The adapter imports spimdisasm and Rabbitizer only when invoked, configures Rabbitizer as `R4000ALLEGREX`, creates one spimdisasm `SectionText` per executable ELF section, runs its native analysis, then translates engine objects into stable `pspdisasm` dataclasses.

Engine-specific classes never leak through the public model. This keeps future spimdisasm/Rabbitizer upgrades localized to one adapter and makes JSON output deterministic.

## Requirements

- Preserve the Phase 1 `analyze` behavior and existing JSON schema fields.
- Add optional runtime dependencies for spimdisasm 1.x / Rabbitizer 1.x analysis while keeping basic executable parsing dependency-light.
- Detect missing engine dependencies and report a typed, actionable error rather than failing at module import time.
- Configure every code section with `rabbitizer.InstrCategory.R4000ALLEGREX`.
- Decode Allegrex-only and VFPU instructions through Rabbitizer, not a local opcode table.
- Run spimdisasm function discovery over each executable section.
- Normalize discovered functions with address, size, section, generated name, and rendered assembly.
- Normalize direct call and branch references with source/target addresses and source function association.
- Normalize data/pointer references produced by spimdisasm and classify targets by Phase 1 section.
- Detect printable NUL-terminated strings at referenced read-only/data addresses and record the decoded value without treating arbitrary bytes as strings.
- Preserve imported/exported NID-derived addresses as seed symbols in the analysis context when they point into mapped executable sections.
- Add a `pspdisasm disasm INPUT [--json OUTPUT] [--asm-dir DIR]` CLI command.
- `--asm-dir` writes one deterministic `.s` file per executable section.
- JSON output includes engine/version metadata so results remain auditable.
- Encrypted `~PSP` containers remain rejected for instruction disassembly until decryption exposes an ELF body.
- Do not copy source code from spimdisasm or Rabbitizer into `pspdisasm`; use their Python APIs.

## Data Model

Phase 2 adds:

- `EngineInfo(name, version)`
- `InstructionRecord(address, word, text, valid, implemented)`
- `FunctionRecord(name, address, size, section, assembly, instruction_count)`
- `SymbolRecord(name, address, section, kind, source)`
- `ReferenceRecord(source_address, target_address, kind, source_function, target_section)`
- `StringRecord(address, value, section, referenced_by)`
- `DisassemblyResult(source_name, engines, functions, symbols, references, strings, assembly_sections, warnings)`

`ExecutableModel` remains the Phase 1 executable metadata object rather than absorbing engine state.

## Analysis Flow

1. Phase 1 parses the raw input into `ExecutableModel` and `ElfImage`.
2. Reject encrypted `~PSP` inputs with `EngineUnavailableError`/`DisassemblyError` explaining that decryption is required.
3. Lazy-load spimdisasm/Rabbitizer and validate compatible 1.x APIs.
4. Create a spimdisasm context covering mapped ELF virtual address ranges.
5. Seed useful known symbols from ELF entrypoint and PSP import/export addresses.
6. For each `Section.kind == "executable"`, instantiate `SectionText` using exact section file bytes and virtual address.
7. Set `instrCat = R4000ALLEGREX`, run `analyze()`, and render assembly.
8. Translate each discovered `SymbolFunction` and its `instrAnalyzer` reference maps into normalized records.
9. Resolve referenced target addresses against Phase 1 sections and perform conservative string recognition.
10. Sort/deduplicate all records deterministically and return `DisassemblyResult`.

## Errors and Warnings

- Missing `spimdisasm`/`rabbitizer`: typed `EngineUnavailableError` with install-extra guidance.
- Encrypted `~PSP`: typed `DisassemblyError` stating that Phase 2 requires decrypted ELF/PRX bytes.
- A code section whose size is not divisible by four: analyze complete words and emit a warning for trailing bytes.
- Engine exceptions are wrapped as `DisassemblyError` with section context while preserving the original exception chain.
- Unmapped reference targets remain in output with `target_section = null`; they are not discarded.

## Testing

Tests use synthetic MIPS/PSP ELF fixtures and the supplied local Rabbitizer/spimdisasm packages. Coverage includes:

- Lazy missing-engine behavior.
- Allegrex-only opcode decoding.
- VFPU opcode decoding.
- Function-boundary discovery around `jr $ra` delay slots.
- Direct `jal` call discovery.
- Branch-target references.
- LUI/addiu or LUI/ori pointer/data references into a mapped section.
- Referenced NUL-terminated ASCII strings.
- Deterministic assembly file names and JSON.
- CLI rejection of encrypted `~PSP` input.
- Full Phase 1 regression suite.

## Non-goals for Phase 2

- PSP cryptographic decryption.
- `PT_PRXRELOC2` decompression/application.
- NID database name resolution.
- Splat project generation.
- m2c decompilation.
- asm-differ integration.
- Whole-program type recovery or high-level control-flow decompilation.
