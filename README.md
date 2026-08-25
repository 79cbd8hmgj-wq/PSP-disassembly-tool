# pspdisasm

`pspdisasm` is a PSP-focused executable analysis and decompilation-orchestration toolkit. The project is designed to connect PSP container/PRX intelligence with the existing Decompollaborate toolchain instead of merging upstream projects into one fork.

## Current status: Phase 1 complete

Phase 1 implements PSP executable intelligence:

- Detects raw ELF32 and `~PSP` container inputs.
- Parses ELF32 headers, program headers, section headers, and section names with bounds validation.
- Recognizes PSP PRX ELF type `0xFFA0`.
- Classifies executable, writable, read-only, BSS, and metadata sections.
- Parses `.rodata.sceModuleInfo` and falls back to the first load header for stripped PRX layouts.
- Walks PSP import and export library tables.
- Preserves unresolved PSP NIDs as machine-readable numeric IDs.
- Parses standard `SHT_REL` and PSP `SHT_PRXRELOC` Type-A relocation records.
- Detects `PT_PRXRELOC2` compressed relocation streams and reports the unsupported decoding boundary explicitly.
- Parses the 0x150-byte `~PSP` outer header without claiming encrypted/compressed executable data is already available.
- Emits deterministic JSON for later disassembly/decompilation phases.

## Usage

Development checkout:

```bash
PYTHONPATH=src python -m pspdisasm analyze path/to/decrypted_EBOOT.BIN
```

JSON output:

```bash
PYTHONPATH=src python -m pspdisasm analyze path/to/module.prx --json analysis.json
```

JSON to stdout:

```bash
PYTHONPATH=src python -m pspdisasm analyze path/to/module.prx --json -
```

After installation, use `pspdisasm` directly.

## Input support

### Raw ELF32 / PRX

Decrypted PSP ELF32 and PRX files can be normalized immediately. PSP PRX files are recognized by `e_type == 0xFFA0` and analyzed for module metadata, library/NID tables, and relocations.

### `~PSP` EBOOT/PRX container

The outer PSP header is parsed, including module name, attributes, compression information, segment metadata, declared ELF/PSP sizes, devkit version, decrypt mode, and subtype. Phase 1 intentionally stops at the cryptographic/decompression boundary. A future decryption backend must expose the underlying ELF before instruction disassembly.

## Upstream tool roles

The approved architecture keeps each source focused on what it already does well:

- **Rabbitizer** — Allegrex instruction decoding, including PSP VFPU.
- **spimdisasm** — MIPS/Allegrex code analysis, functions, symbols, references, and sections.
- **Splat** — PSP-aware project splitting/configuration and decomp project generation.
- **m2c** — optional approximate assembly-to-C backend; kept out-of-process because of its GPLv3 license.
- **asm-differ** — recompilation/matching diff workflow.

`pspdisasm` is the PSP-specific orchestration and executable-intelligence layer around those components.

## Phase 2 handoff

Phase 2 will consume `ExecutableModel` and add a spimdisasm/Rabbitizer adapter configured for `r4000allegrex`. Its first outputs should be:

- Allegrex/VFPU assembly per executable section.
- Function and symbol candidates.
- branch/jump/call references.
- pointer and string references.
- machine-readable function metadata for Splat project generation.

## Deliberate Phase 1 limitations

- No PSP cryptographic decryption.
- No GZIP/KL4E/2RLZ decompression of encrypted `~PSP` bodies.
- No `PT_PRXRELOC2` decompression yet.
- No instruction disassembly or function discovery yet.
- No NID-to-name database yet.
- No ISO/CSO filesystem extraction yet.

These are explicit extension boundaries, not silent fallbacks.

## Development

Run tests:

```bash
PYTHONPATH=src python -m pytest -q
```

The test fixtures are synthetic PSP-like ELF/PRX structures; no commercial game data is included.
