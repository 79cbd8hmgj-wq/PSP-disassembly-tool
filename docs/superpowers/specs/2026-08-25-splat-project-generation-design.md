# PSP Splat Project Generation Design

## Goal
Generate a self-contained Splat 0.50.0 PSP decompilation workspace from a decrypted PSP ELF/PRX using Phase 1 metadata and Phase 2 Allegrex analysis.

## Source-grounded constraints
The supplied Splat 0.50.0 source supports `platform: psp`, defaults PSP to little-endian, selects Rabbitizer `R4000ALLEGREX` for PSP code subsegments, and documents `asm`, `data`, `rodata`, `bss`, and `code` segment types. Its ELF quickstart converts ELF loadable content into a flat ROM before splitting and seeds `symbol_addrs.txt` with an entry function. We follow those conventions rather than feeding ELF metadata bytes to code segments.

## Architecture
`pspdisasm project INPUT OUTPUT` parses the ELF, runs Phase 2 analysis, creates a VRAM-linear flat target image from allocated file-backed sections, and emits a Splat configuration whose ROM offsets equal `section.addr - image_base`. One top-level `code` segment contains section-derived subsegments; gaps become `bin` subsegments and NOBITS sections become explicit `bss` subsegments.

The workspace contains `splat.yaml`, `target.bin`, `config/symbols.txt`, empty undefined-symbol files, Phase 1/2 JSON metadata, Phase 2 assembly, and empty `src/`, `build/`, and `reports/` directories. Symbols discovered by Phase 2 are translated to Splat symbol syntax conservatively; entrypoint and discovered functions use `type:func`, referenced strings use `type:asciz`, and other symbols are left to Splat inference.

## Error handling
Encrypted `~PSP` inputs are rejected because project generation requires decrypted ELF bytes. ELF images without allocated file-backed sections are rejected. Excessively sparse VRAM images (>128 MiB) are rejected rather than allocating unbounded memory.

## Validation
Tests verify flattening, section-to-segment mapping, symbol generation, deterministic project output, CLI behavior, and Phase 1/2 regression. Generated YAML is parsed with PyYAML and checked against the supplied Splat 0.50.0 documented PSP schema/conventions.
