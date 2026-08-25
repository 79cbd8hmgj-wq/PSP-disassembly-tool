# pspdisasm

`pspdisasm` is a PSP-focused executable-analysis and decompilation-orchestration toolkit. It adds PSP container/PRX intelligence around the Decompollaborate ecosystem instead of merging upstream projects into one fork.

## Current status: Phase 3

The project now covers three layers:

### Phase 1 — PSP executable intelligence

- Detects raw ELF32 and `~PSP` container inputs.
- Parses ELF32 headers, program headers, section headers, and section names with bounds validation.
- Recognizes PSP PRX ELF type `0xFFA0`.
- Classifies executable, writable, read-only, BSS, metadata, and relocation sections.
- Parses `.rodata.sceModuleInfo`, with stripped-PRX fallback.
- Walks PSP import/export library tables and preserves unresolved NIDs.
- Parses standard `SHT_REL` and PSP `SHT_PRXRELOC` Type-A relocations.
- Detects `PT_PRXRELOC2` compressed relocation streams without silently mis-decoding them.
- Parses the 0x150-byte `~PSP` outer header and reports the decryption boundary.

### Phase 2 — Allegrex disassembly and discovery

- Uses **Rabbitizer 1.x** with `InstrCategory.R4000ALLEGREX`.
- Decodes PSP Allegrex-only instructions and VFPU instructions.
- Uses **spimdisasm 1.x** for function-boundary and instruction-reference analysis.
- Discovers functions from code flow and direct `jal` targets.
- Records direct calls and branch targets with source-function association.
- Records LUI/LO address materialization and maps targets back to ELF sections.
- Normalizes discovered symbols without leaking spimdisasm classes into the public API.
- Conservatively recognizes referenced NUL-terminated UTF-8 strings.
- Emits deterministic JSON containing engine versions, functions, instructions, symbols, references, strings, and generated assembly.
- Writes one `.s` file per executable section.

## Installation

Basic executable/PRX parsing has no mandatory third-party runtime dependency:

```bash
python -m pip install -e .
```

Install the Phase 2 disassembly engines with the analysis extra:

```bash
python -m pip install -e '.[analysis]'
```

The analysis extra installs spimdisasm 1.x, which depends on Rabbitizer 1.x.

### Developing against supplied local engine source

When testing an exact local Rabbitizer/spimdisasm source checkout instead of installed packages, build Rabbitizer's extension in its source directory and include both source roots on `PYTHONPATH`:

```bash
cd /path/to/rabbitizer-1.x
python setup.py build_ext --inplace

cd /path/to/PSP-disassembly-tool
PYTHONPATH="src:/path/to/rabbitizer-1.x:/path/to/spimdisasm-1.x" python -m pytest -q
```

## Commands

### Analyze PSP executable metadata

```bash
pspdisasm analyze path/to/decrypted_EBOOT.BIN
```

Write normalized metadata JSON:

```bash
pspdisasm analyze path/to/module.prx --json executable.json
```

### Disassemble Allegrex code

```bash
pspdisasm disasm path/to/decrypted_EBOOT.BIN
```

Write full normalized analysis JSON:

```bash
pspdisasm disasm path/to/decrypted_EBOOT.BIN --json disassembly.json
```

Write assembly files and JSON together:

```bash
pspdisasm disasm path/to/decrypted_EBOOT.BIN \
  --asm-dir asm \
  --json disassembly.json
```

A code section such as `.text` is written as `asm/text.s`. Duplicate sanitized section names receive a deterministic address suffix.

## Phase 2 output

The normalized disassembly result includes:

- exact spimdisasm and Rabbitizer versions;
- discovered functions and instruction records;
- per-function and per-section assembly;
- function/code/data symbols;
- call, branch, and data references;
- mapped target section names;
- referenced strings and the instruction addresses that reference them;
- analysis warnings.

Example high-level structure:

```text
DisassemblyResult
├── engines
├── functions
│   └── instructions
├── symbols
├── references
├── strings
├── assembly_sections
└── warnings
```

## `~PSP` EBOOT/PRX containers

The outer PSP header is parsed, including module name, attributes, compression information, segment metadata, declared ELF/PSP sizes, devkit version, decrypt mode, and subtype.

Instruction disassembly intentionally stops at the cryptographic/decompression boundary. `pspdisasm disasm` requires decrypted ELF/PRX bytes; it does not pretend an encrypted `~PSP` body is executable code.

## Upstream tool roles

The architecture keeps each source focused on what it already does well:

- **Rabbitizer** — Allegrex/VFPU instruction decoding.
- **spimdisasm** — MIPS/Allegrex function, symbol, and reference analysis.
- **Splat** — PSP-aware project splitting/configuration conventions used by Phase 3 project generation.
- **m2c** — optional approximate assembly-to-C backend in a later phase; kept out-of-process because of GPLv3.
- **asm-differ** — recompilation/matching workflow in a later phase.

`pspdisasm` remains the PSP-specific orchestration and executable-intelligence layer around those components.

## Current limitations

- No PSP cryptographic decryption.
- No GZIP/KL4E/2RLZ decompression of encrypted `~PSP` bodies.
- No `PT_PRXRELOC2` decompression/application yet.
- No NID-to-name database yet.
- No ISO/CSO filesystem extraction yet.
- No m2c or asm-differ command integration yet.
- No high-level C recovery/type reconstruction yet.

## Development

Run the complete suite with installed analysis engines:

```bash
PYTHONPATH=src python -m pytest -q
```

The tests use synthetic PSP-like ELF/PRX structures. No commercial game data is included.

## Phase 3: Splat project generation

Generate a Splat-ready PSP decompilation workspace from a decrypted ELF/PRX:

```bash
pspdisasm project decrypted_EBOOT.BIN game_decomp
```

The generated project contains:

```text
game_decomp/
├── splat.yaml
├── target.bin
├── config/
│   ├── symbols.txt
│   ├── undefined_funcs_auto.txt
│   └── undefined_syms_auto.txt
├── metadata/
│   ├── executable.json
│   ├── disassembly.json
│   ├── functions.json
│   ├── symbols.json
│   ├── references.json
│   └── strings.json
├── asm/
│   └── nonmatchings/
├── src/
├── build/
├── assets/
└── reports/
```

Phase 3 follows the supplied Splat 0.50.0 PSP conventions: `platform: psp`, little-endian MIPS, Rabbitizer's `R4000ALLEGREX` path, a `code` segment containing `asm`/data/rodata/BSS subsegments, and `symbol_addrs.txt`-style symbol declarations. The original ELF metadata is not fed to Splat as code; allocated ELF sections are normalized into a flat VRAM-linear `target.bin`, following Splat's ELF quickstart model.
