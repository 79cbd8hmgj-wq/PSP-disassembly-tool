# Phase 7A — PSP Game-Image Ingestion Implementation Plan

Date: 2026-08-26

## Objective

Add a clean whole-game input boundary to `pspdisasm` so ISO and standard CSO images can be inspected, indexed and reduced to executable modules without depending on PPSSPP or pycdlib at runtime.

## Work items

### 1. Raw ISO ingestion

- Add a file-backed random-access reader.
- Validate the PSP-relevant ISO9660 primary volume descriptor.
- Parse directory records recursively.
- Preserve disc paths, extents, sizes and directory identity.
- Strip numeric ISO9660 version suffixes.
- Reject malformed/truncated records deterministically.

Verification: synthetic ISO fixture identifies `/PSP_GAME/SYSDIR/EBOOT.BIN` and selects it as the boot module.

### 2. Standard CSO random access

- Detect `CISO` by magic.
- Parse the canonical 24-byte v0/v1 header.
- Read and validate the block index.
- Support stored blocks and raw-DEFLATE blocks.
- Support logical reads spanning multiple compressed blocks.
- Keep the filesystem layer independent from image compression.

Verification: the exact same PSP ISO fixture compressed into CSO is indexed without full decompression.

### 3. PARAM.SFO metadata

- Implement bounded SFO header/index/key/data parsing.
- Decode UTF-8 strings and 32-bit integers.
- Preserve binary/unknown values as JSON-safe hexadecimal.
- Load `/PSP_GAME/PARAM.SFO` during image analysis.
- Treat malformed optional metadata as a warning rather than disc failure.

Verification: synthetic metadata returns expected `DISC_ID`, `TITLE` and integer fields.

### 4. Executable inventory and extraction

- Identify ELF and `~PSP` files by content magic.
- Prefer valid `EBOOT.BIN`, then valid `BOOT.BIN` for boot selection.
- Expose one-file random access by normalized disc path.
- Extract all discovered executable modules while preserving disc-relative paths.
- Reject path traversal components.
- Keep extraction bounded to the declared ISO file extent.
- Reuse one image index/reader for bulk extraction.

Verification: executable bytes extracted directly from CSO exactly match their original ISO contents.

### 5. CLI

Add:

```text
pspdisasm game INPUT [--json PATH|-] [--extract DIR]
```

Output should include:

- image format;
- logical size;
- filesystem inventory;
- executable inventory;
- selected boot path;
- PARAM.SFO metadata;
- warnings;
- extracted module paths.

Verification: CLI JSON remains valid when extraction is requested and the expected EBOOT is written.

### 6. Public package boundary

Export:

- `analyze_game_image`;
- `read_game_file`;
- `extract_game_executables`;
- `parse_param_sfo`.

Advance package version to `0.10.0` and update previous compatibility tests to assert the new current version while preserving Phase 6 API checks.

### 7. Documentation and licensing boundary

Record:

- PPSSPP as behavioral reference only;
- maxcso as CSO format reference;
- pycdlib as ISO9660 maturity/reference source;
- no copied GPL/LGPL implementation code;
- CSO v2/ZSO/DAX and PSP decryption outside Phase 7A;
- Phase 7B as the game-wide per-module analysis/linking handoff.

## Completion criteria

Phase 7A is complete when:

1. ISO and standard CSO fixtures produce the same filesystem/boot result.
2. PARAM.SFO metadata is decoded conservatively.
3. ELF/~PSP modules can be extracted without unpacking the whole image.
4. `pspdisasm game` exposes normalized machine-readable output.
5. Earlier public APIs remain available.
6. The full repository test suite passes on the PR head.
7. The PR diff is reviewed for correctness, boundary safety and licensing isolation before merge.
