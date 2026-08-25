# PSP Executable Intelligence Design

## Goal

Build Phase 1 of the approved `pspdisasm` architecture: normalize decrypted PSP ELF/PRX executables and encrypted `~PSP` containers into a machine-readable executable model that later phases can feed into spimdisasm, Rabbitizer, Splat, m2c, and asm-differ.

## Architecture

`pspdisasm` is a standalone Python package. It does not merge upstream codebases. The Phase 1 core uses Python's standard library to parse the container and executable metadata, exposes stable dataclasses, and keeps future engine integrations behind adapters.

Inputs are classified as:

- ELF32 (`0x7FELF`), including PSP PRX (`e_type == 0xFFA0`).
- Encrypted/compressed PSP container (`~PSP`), whose outer header is parsed but whose executable body remains unavailable until a decryption backend is added.

## Requirements

- Parse ELF32 headers, program headers, section headers, and section-name string tables.
- Validate bounds before reading structures.
- Classify executable, writable, read-only, BSS, and relocation sections.
- Recognize PSP PRX ELF type `0xFFA0`, PSP relocation section `0x700000A0`, and relocation program segments `0x700000A0`/`0x700000A1`.
- Parse standard 8-byte MIPS/PSP relocation records from `SHT_REL` and `SHT_PRXRELOC` sections.
- Report compressed PRX relocation type 2 segments as present even before decompression support is implemented.
- Parse `.rodata.sceModuleInfo`, with fallback location derived from the first load program header when section metadata is absent.
- Parse PSP import/export library tables and preserve unresolved NIDs as numeric IDs.
- Parse the 0x150-byte `~PSP` outer header and report that decryption is required when the body is not directly available as ELF.
- Emit deterministic JSON suitable for later phases.
- Provide `pspdisasm analyze INPUT [--json OUTPUT]`.
- Avoid copying GPL `m2c` code into the core; m2c remains an optional out-of-process backend in a later phase.
- Python >= 3.10; no mandatory third-party runtime dependencies for Phase 1.

## Non-goals for Phase 1

- Instruction disassembly.
- Function discovery.
- Applying relocations to construct a rebased image.
- PT_PRXRELOC2 decompression.
- NID-to-name resolution database.
- PSP cryptographic decryption/decompression.
- ISO/CSO extraction.

## Data Flow

1. Read bytes and detect input kind.
2. For `~PSP`, parse outer metadata and stop at the encrypted/decompression boundary unless a raw ELF is directly identifiable.
3. For ELF32, parse/validate ELF structures.
4. Normalize program/section metadata.
5. If PRX, locate module info and walk import/export tables through virtual-address-to-file-offset mapping.
6. Collect relocation records and warnings.
7. Serialize the model to JSON or print a concise human summary.

## Error Handling

Malformed offsets, truncated structures, unsupported ELF class/endianness, or impossible table bounds raise a typed `ParseError`. Recoverable PSP metadata issues become warnings so a partially useful executable model can still be returned.

## Testing

Tests use synthetic little-endian MIPS ELF/PRX fixtures so validation is deterministic and does not require distributing a game binary. Tests cover malformed input, encrypted `~PSP` headers, program/section parsing, module-info fallback, import/export NIDs, relocations, and CLI JSON output.
