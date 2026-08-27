# Phase 7F — Explicit relocated load views

Phase 7F turns the relocation metadata decoded in Phase 7E into an explicit, caller-controlled runtime view for a single decrypted PSP ELF/PRX. It does not choose a PSP runtime address automatically and it does not mutate the original input bytes.

## Public API

```python
from pspdisasm import RelocatedLoadView, build_relocated_load_view

view = build_relocated_load_view(
    data,
    elf,
    model,
    load_address=0x08900000,
)
```

`load_address` is required and is interpreted as the requested runtime address of the lowest-addressed `PT_LOAD` segment in the input image.

`RelocatedLoadView` records:

- the requested `load_address`;
- the original image base;
- the applied image-wide address delta;
- the resulting base of each `PT_LOAD` segment;
- the number of relocation words processed;
- a new relocated `ElfImage`;
- a new normalized `ExecutableModel`.

The source `bytes`, source `ElfImage`, and source `ExecutableModel` are not modified in place.

## Address rebasing

The relocated view computes:

```text
original_image_base = min(PT_LOAD.vaddr)
address_delta       = load_address - original_image_base
```

Every loadable segment retains its original relative placement and receives the same image-wide delta.

The view rebases:

- `PT_LOAD` virtual and physical addresses;
- allocated ELF section addresses;
- the ELF entrypoint when it lies inside an original loaded segment;
- normalized PRX module/import/export/NID metadata addresses only when the original address can be proven to lie inside a loaded segment.

Module import/export end pointers are range boundaries: an end pointer exactly equal to the end of a loaded segment receives the same image-wide delta as the corresponding range start.

Values that do not map to an original loaded segment are preserved. Phase 7F therefore does not reinterpret arbitrary integers or external addresses as module-local pointers.

## Relocation application

Relocations are applied to a copy of the original bytes before the relocated ELF is handed to downstream analysis.

For PSP Type-A relocations, the source and target segment identities are taken from explicit normalized provenance when available, otherwise from the PSP segment fields encoded in `r_info`.

For Phase 7E Type-B relocations, the already-normalized source/target segment provenance is reused directly.

The target base supplied to `apply_psp_relocation_word()` is the relocated base of the relocation's target `PT_LOAD` segment.

Supported normalized relocation behavior includes:

- `R_MIPS_NONE` — identity;
- `R_MIPS_16` — low-half relocation;
- `R_MIPS_32` — full-word relocation;
- `R_MIPS_26` — jump-field relocation;
- `R_MIPS_HI16` — paired high-half relocation;
- `R_MIPS_LO16` — low-half relocation;
- `R_MIPS_GPREL16` — preserved unchanged for the PSP load-view operation;
- `R_MIPS_X_J26` — relocated jump with forced `j` opcode;
- `R_MIPS_X_JAL26` — relocated jump with forced `jal` opcode.

Unsupported relocation types fail closed instead of being guessed.

## Type-A HI16 state

Type-A `R_MIPS_HI16` records do not carry the complete low-half state in the relocation entry itself. Phase 7F resolves the required signed low half from a later compatible `R_MIPS_LO16` or `R_MIPS_16` relocation in the same source/target segment pair.

A missing compatible low-half companion is not guessed. The existing Phase 7E rule also remains in force for Type-B HI16 reuse state: ambiguous reuse remains unresolved unless an explicit low half is available.

## Bounds and immutability

Relocation writes are permitted only when the source relocation identifies a complete four-byte word inside the file-backed portion of a valid `PT_LOAD` segment.

Phase 7F rejects:

- non-little-endian PSP load views;
- load addresses outside unsigned 32-bit range;
- rebased `PT_LOAD` or allocated-section ranges that would extend outside the 32-bit address space;
- inputs with no loadable segment;
- invalid source/target segment indices;
- relocation source segments that are not `PT_LOAD`;
- relocation words outside the file-backed source range;
- relocation writes that would extend beyond the supplied input;
- unresolved relocation state required for safe application;
- unsupported relocation types.

No fallback scanner rewrites constants merely because they resemble PSP addresses.

## Downstream integration

`disassemble_bytes()` and `disassemble_file()` accept optional `load_address=`. When it is provided, spimdisasm receives the relocated ELF/model pair.

`build_project_artifacts()` and `generate_project()` also accept optional `load_address=`. A single relocated view then feeds:

- spimdisasm;
- advanced analysis;
- NID linking and symbol propagation;
- Phase 6C data typing;
- Phase 6D asset discovery;
- ELF flattening into `target.bin`;
- Splat VRAM configuration;
- generated symbol and metadata files.

This prevents a project from mixing raw image addresses with relocated runtime addresses.

Phase 6C additionally resolves PSP relocation slots through their source `PT_LOAD` segment. Legacy non-PSP/older absolute relocation fixtures retain their prior compatible interpretation.

## CLI

Single-module disassembly can request a runtime address explicitly:

```bash
pspdisasm disasm module.prx --load-address 0x08900000
```

Single-module project generation supports the same address, in decimal or `0x` hexadecimal form:

```bash
pspdisasm project module.prx game_decomp --load-address 0x08900000
```

Omitting `--load-address` preserves the existing non-rebased workflow.

## Whole-game boundary

Phase 7F deliberately does **not** add one global `--load-address` to `game-project`.

A PSP game can contain multiple independently loaded PRX modules, so one user-supplied address cannot safely describe every module. Phase 7G now owns that separate concern: it preserves fixed `ET_EXEC` addresses, infers the selected relocatable boot module from PSP allocator evidence, and assigns secondary relocatable PRXs explicitly analysis-only placements when their exact runtime address is not recoverable from the disc image.

See [`phase7g-runtime-placement.md`](phase7g-runtime-placement.md) for the evidence/confidence model and whole-game integration.

## Reference and licensing boundary

PPSSPP was used only as a behavioral reference for PSP relocation/loading semantics, including Type-A segment fields and PSP relocation behavior. GPL implementation code is not copied into the MIT core.

Phase 7F continues the clean-room boundary established in earlier phases: upstream projects define behavior and interoperability targets; `pspdisasm` implements its own bounded Python orchestration and normalized models.