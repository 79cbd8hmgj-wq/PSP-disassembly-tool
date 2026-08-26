# Phase 7A Disc Intake Design

## Purpose

Phase 7A makes `pspdisasm` accept whole PSP game disc images instead of requiring a manually extracted executable. Its responsibility ends at producing a normalized, deterministic game-disc manifest and extracting the executable candidates needed by the existing analyzer/disassembler pipeline.

Full per-module disassembly, cross-module linking, and unified decompilation-project generation are intentionally deferred to Phase 7B so the disc reader remains independently testable.

## Source findings

The implementation is informed by three added reference sources:

- **PPSSPP** documents PSP disc conventions and boot selection behavior: `PSP_GAME/PARAM.SFO`, `UMD_DATA.BIN`, primary `PSP_GAME/SYSDIR/EBOOT.BIN`, and fallback `PSP_GAME/SYSDIR/BOOT.BIN`. PPSSPP is used as a behavioral reference only; no GPL implementation is copied into the MIT project.
- **maxcso** documents CISO v1/v2 block layout. Its ISC-licensed format documentation is used to implement a small clean-room CSO reader in Python.
- **pycdlib** provides mature ISO9660 traversal. It remains an optional runtime dependency under LGPL-2.1; its source is not copied into this repository.

## Scope

Phase 7A accepts:

- raw ISO9660 `.iso` images;
- `CISO`/`.cso` version 0/1 images using raw DEFLATE blocks;
- CISO version 2 images using raw DEFLATE or LZ4 blocks when the optional `lz4` dependency is installed.

It does not yet support ZSO, DAX, encrypted NPISO/PBP containers, UMD Video, or UMD Audio.

## Public workflow

A new command is added:

```bash
pspdisasm game GAME.iso OUTPUT_DIR
pspdisasm game GAME.cso OUTPUT_DIR
```

The command produces:

```text
OUTPUT_DIR/
├── metadata/
│   ├── disc.json
│   └── param_sfo.json
└── modules/
    ├── PSP_GAME/SYSDIR/EBOOT.BIN
    ├── PSP_GAME/SYSDIR/BOOT.BIN        # only when present/relevant
    └── ... discovered PRX/executable candidates
```

`metadata/disc.json` is the canonical machine-readable inventory for Phase 7B.

## Architecture

### `disc_image.py`

Owns image-format detection and random-access block reading.

- `DiscImageFormat`: `iso`, `cso`.
- `CsoHeader`: normalized CISO header fields.
- `CsoReader`: seekable/readable virtual uncompressed ISO stream backed by an on-disk CSO.
- `open_disc_stream(path)`: context manager yielding `(format, seekable_binary_stream)`.

The CSO reader validates header size, block size, index length, monotonic block offsets, and decompressed block sizes before returning data. CISO v1 uses the high index bit as the uncompressed flag. CISO v2 treats blocks whose stored span is at least the logical block size as uncompressed; smaller blocks use DEFLATE unless the high bit requests LZ4.

No whole-image decompression is performed.

### `sfo.py`

Implements the small PARAM.SFO/PSF parser required for game identity. It accepts the `\0PSF` header, validates table boundaries, and returns a dictionary containing string and integer values. Phase 7A surfaces `TITLE`, `DISC_ID`, `DISC_VERSION`, `PSP_SYSTEM_VER`, `CATEGORY`, and `MEMSIZE` when present, while preserving all parsed keys in `param_sfo.json`.

### `disc.py`

Owns PSP-specific ISO traversal and manifest generation. It dynamically imports `pycdlib`; if unavailable it raises an actionable backend-unavailable error instructing the user to install the `disc` extra.

ISO9660 version suffixes such as `;1` are stripped only from logical manifest paths. The physical ISO path is retained internally for extraction.

The scanner records every file with normalized PSP-style path, size, and classification. Classification values are:

- `metadata` for `PARAM.SFO`, `UMD_DATA.BIN`, and similar top-level PSP metadata;
- `boot` for the selected executable;
- `module` for `.PRX` files and additional files whose first four bytes are `~PSP` or ELF magic;
- `resource` for all other files.

The preferred boot candidate is `PSP_GAME/SYSDIR/EBOOT.BIN` when its magic is `~PSP` or ELF. If that file is absent or not executable, `PSP_GAME/SYSDIR/BOOT.BIN` is selected when executable. PPSSPP's translation-patch filename exceptions are deliberately not reproduced in Phase 7A because they are emulator compatibility heuristics rather than standard PSP disc structure.

Only the selected boot file and discovered executable/module candidates are physically extracted. Output paths are derived from normalized disc paths and are rejected if they could escape `OUTPUT_DIR/modules`.

## Data model

`model.py` gains:

- `DiscFileRecord(path, size, classification, executable_kind)`
- `GameModuleRecord(path, size, executable_kind, output_path, is_boot)`
- `GameDiscManifest(source_name, image_format, title, disc_id, disc_version, psp_system_version, boot_path, files, modules, warnings)`

`executable_kind` is `elf`, `psp_container`, or `unknown`.

The manifest serializes deterministically with file and module records sorted case-insensitively by path.

## Dependency boundary

`pyproject.toml` adds an optional extra:

```toml
[project.optional-dependencies]
disc = ["pycdlib>=1.14,<2", "lz4>=4.3,<5"]
```

Neither dependency is imported by the existing executable-only commands. `analyze`, `disasm`, `project`, `link`, `decompile`, and `match` continue to work with the existing installation footprint.

## Error handling

Phase 7A rejects:

- unsupported disc magic;
- malformed/truncated CISO headers or index tables;
- non-monotonic/out-of-range CISO block offsets;
- decompressed blocks with the wrong logical size;
- invalid ISO9660 filesystems;
- PSP discs that contain no usable EBOOT/BOOT executable;
- unsafe extraction paths.

Errors use existing `ParseError`/`EngineUnavailableError` boundaries so CLI behavior remains consistent.

## Testing

Tests are synthetic and do not require copyrighted game images.

- CISO tests construct tiny in-memory/raw files with plain and DEFLATE blocks and verify random seek/read behavior.
- CISO v2 LZ4 behavior is covered when `lz4` is installed.
- PARAM.SFO tests build a minimal PSF fixture and validate strings, integers, and malformed bounds.
- Disc tests build a tiny ISO using pycdlib containing `PARAM.SFO`, `EBOOT.BIN`, one `.PRX`, and one resource, then verify boot choice, classification, manifest determinism, and extraction.
- CLI tests verify `pspdisasm game` creates metadata and module output and reports missing optional dependencies clearly.

## Phase 7B handoff

Phase 7B will consume `GameDiscManifest.modules`, run the existing executable analyzer/disassembler on every decrypted ELF/PRX candidate, skip encrypted `~PSP` modules with explicit warnings until a legal decryption backend is supplied, apply existing NID/cross-module linking, and generate a unified game project. Phase 7A does not duplicate those responsibilities.
