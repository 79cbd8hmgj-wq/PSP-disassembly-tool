# Phase 7A — PSP Game-Image Ingestion Design

Date: 2026-08-26

## Goal

Extend `pspdisasm` from executable/module inputs to whole PSP game images without coupling the MIT core to GPL/LGPL implementations. Phase 7A is the ingestion boundary only: it discovers and safely extracts executable modules from ISO/CSO images and exposes disc metadata for later orchestration.

The intended flow is:

```text
ISO / CSO
   |
   v
block reader
   |
   v
ISO9660 filesystem index
   |---------------------> PARAM.SFO metadata
   |
   v
ELF / ~PSP executable discovery
   |
   v
safe per-module extraction
   |
   v
Phase 7B: existing analyze/disasm/link/project pipeline
```

## Source audit and licensing boundary

Three new reference sources were supplied for this phase.

### PPSSPP

PPSSPP is the behavioral reference for PSP disc layout and boot semantics. Relevant behavior includes mounting ISO-backed `disc0:`, reading `/PSP_GAME/PARAM.SFO`, locating `/PSP_GAME/SYSDIR/EBOOT.BIN`, and falling back to `BOOT.BIN` where appropriate.

PPSSPP code is not copied into `pspdisasm`. It is used only to verify PSP-specific behavior and file locations.

### maxcso

maxcso documents the standard CISO/CSO layout used by PSP images. The core format implementation is suitable as a format reference, including:

- 24-byte `CISO` header;
- logical uncompressed size;
- power-of-two block size;
- block index table;
- index shift;
- high-bit uncompressed-block marker for CSO v1;
- raw DEFLATE compressed blocks.

Phase 7A implements only standard CSO v0/v1 semantics. CSO2, ZSO and DAX are intentionally outside this slice.

### pycdlib

pycdlib is the maturity/reference point for ISO9660 behavior. The Phase 7A core does not vendor or import pycdlib; the implementation remains dependency-free beyond the existing package requirements and handles the conservative ISO9660 subset PSP UMD game images require.

## Supported inputs

Phase 7A accepts:

- raw ISO9660 PSP game images;
- standard CSO/CISO version 0 or 1 images using raw DEFLATE compression.

Format selection is based on file magic rather than filename extension.

## Deliberate exclusions

Phase 7A does not claim support for:

- CSO v2;
- ZSO;
- DAX;
- arbitrary UDF filesystems;
- Joliet/Rock Ridge metadata as a requirement;
- PSP executable decryption or KIRK emulation;
- recursive asset extraction from the whole disc;
- automatic analysis/project generation for every discovered module;
- game-specific archives or resource-manager reconstruction.

Those boundaries keep this phase narrowly testable and prevent it from conflating disc ingestion with executable decryption and game-wide analysis.

## Block-reader abstraction

The filesystem parser consumes a small random-access reader contract:

```text
size: int
image_format: str
read(offset, size) -> bytes
close()
```

### Raw ISO reader

The raw reader performs bounded seeks directly against the source file. It never loads the entire image into memory.

### CSO reader

The CSO reader parses the block table once and maps logical reads onto compressed or stored blocks. It validates:

- recognized `CISO` magic;
- supported version;
- logical size greater than zero;
- power-of-two block size at least 2048 bytes;
- bounded index shift;
- complete block-index table;
- monotonic physical offsets;
- offsets inside the compressed file;
- exact decompressed block size.

A single decompressed block is cached because ISO9660 directory and metadata reads commonly touch the same sector repeatedly.

The declared CSO header-size field is not used to relocate the v0/v1 index table. Real-world PSP tooling commonly treats the canonical 24-byte header as the index boundary, matching established loader behavior and avoiding reliance on historically unreliable header-size values.

## ISO9660 indexing

The Phase 7A ISO layer:

1. validates the ISO9660 primary volume descriptor and 2048-byte logical sector size;
2. parses the root directory record;
3. recursively walks directory extents;
4. ignores `.` and `..` records;
5. strips numeric ISO version suffixes such as `;1`;
6. retains virtual disc path, size, extent and directory/file identity;
7. tracks visited directory extents to prevent malformed recursive loops;
8. rejects truncated or malformed records instead of silently guessing.

Paths are normalized to forward-slash absolute disc paths such as:

```text
/PSP_GAME/SYSDIR/EBOOT.BIN
```

## PSP executable discovery

Every file-backed directory entry is checked by content magic, not extension.

Accepted executable/container identities are:

- `0x7F 'E' 'L' 'F'` -> `elf`;
- `~PSP` -> `encrypted_psp_container`.

The preferred boot module is `/PSP_GAME/SYSDIR/EBOOT.BIN` when it has a recognized executable/container magic. If that is unavailable or invalid, `/PSP_GAME/SYSDIR/BOOT.BIN` is considered.

All recognized executable files remain in the inventory, not only the selected boot module. This is the handoff required for Phase 7B cross-module analysis.

## PARAM.SFO

`/PSP_GAME/PARAM.SFO` is parsed when present. The decoder validates header/table boundaries and supports the common PSP value classes:

- UTF-8 string (`0x0204`);
- 32-bit little-endian integer (`0x0404`);
- binary/unknown fields retained as hexadecimal text so normalized JSON remains serializable.

Malformed SFO metadata does not invalidate an otherwise readable game image. It produces a deterministic warning and leaves `param_sfo` empty.

## Public API

Phase 7A exposes:

```python
from pspdisasm import (
    analyze_game_image,
    extract_game_executables,
    parse_param_sfo,
    read_game_file,
)
```

`analyze_game_image(path)` returns a normalized `GameImageAnalysis` containing:

- source name;
- image format;
- logical image size;
- sector size;
- filesystem entries;
- discovered executables;
- selected boot path;
- decoded PARAM.SFO metadata;
- warnings.

`read_game_file(path, disc_path)` reads one exact file from ISO or CSO without unpacking the whole image.

`extract_game_executables(path, output_dir)` indexes the game image once, then writes all recognized ELF/~PSP modules while preserving their disc-relative directory structure.

## Extraction safety

Extraction never treats an arbitrary user path as an output path. It only writes paths originating from the indexed ISO inventory and rejects traversal components such as `.` and `..` before creating output paths.

No heuristic carving is performed. Extracted size is exactly the ISO9660 file size declared by the accepted directory record.

## CLI

The new command is:

```bash
pspdisasm game game.iso
pspdisasm game game.cso --json game.json
pspdisasm game game.cso --extract extracted_modules
pspdisasm game game.iso --json - --extract extracted_modules
```

The normalized JSON output contains filesystem/executable inventories, boot selection, PARAM.SFO metadata, warnings, `file_count`, and any paths extracted by the command.

## Version

Phase 7A advances the package to `pspdisasm 0.10.0`.

## Phase 7B handoff

Phase 7B should consume the Phase 7A inventory and run the existing executable pipeline per discovered module:

```text
ISO/CSO inventory
  -> executable materialization
  -> executable analysis
  -> Allegrex/VFPU disassembly where decryptable
  -> NID resolution
  -> cross-module linking
  -> unified game project metadata
```

Encrypted `~PSP` containers must remain explicit until a separately designed decryption boundary exists. Phase 7B must not pretend encrypted retail modules are already analyzable Allegrex code.
