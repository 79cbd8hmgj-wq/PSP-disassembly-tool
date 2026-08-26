# Phase 7C — Game-wide resource orchestration

Phase 7C extends the Phase 7B whole-game pipeline beyond executable modules. `game-project` now inventories and extracts non-executable disc resources, classifies supported formats from file content, scans smaller loose files for embedded supported resources, and preserves unknown proprietary files without guessing their structure.

## Command

```bash
pspdisasm game-project game.iso game_decomp
pspdisasm game-project game.cso game_decomp --nid-db psp_nids.csv
```

The lightweight `pspdisasm game` command remains Phase 7A-only: it inventories the disc and extracts executable candidates but does not copy or analyze all resource files.

## Supported resource signatures

Phase 7C shares the same conservative byte-level detector layer used by Phase 6D:

- PNG
- JPEG
- RIFF/WAVE
- ATRAC-family RIFF/WAVE as AT3
- VAG audio
- PSP GIM images
- PSMF/PMF video

A filename extension alone never establishes the format. A loose file is considered known only when a supported detector accepts a content match at offset zero with confidence at least `0.90`.

Malformed signatures remain `unknown` rather than being force-classified.

## Output layout

```text
game_decomp/
├── metadata/
│   ├── disc.json
│   ├── param_sfo.json
│   ├── game_analysis.json
│   ├── module_links.json
│   ├── propagated_symbols.json
│   ├── game_resources.json
│   └── embedded_resources.json
├── reports/
│   └── game_resources.csv
├── modules/
│   └── PSP_GAME/... executable candidates ...
├── projects/
│   └── PSP_GAME/... per-module Splat projects ...
└── resources/
    ├── files/
    │   └── PSP_GAME/... non-executable disc files ...
    └── embedded/
        └── PSP_GAME/.../<OFFSET>_<format>.<ext>
```

## Loose-file inventory

Every Phase 7A `resource` file is copied beneath `resources/files/` using its normalized logical disc path.

Each `GameResourceRecord` records:

- logical disc path;
- extracted relative path;
- file size;
- detected format or `unknown`;
- resource kind (`image`, `audio`, `video`, or `unknown` for the current built-in set);
- confidence;
- detection evidence;
- suggested extension;
- detector metadata;
- embedded-resource count;
- resource-local warnings.

The normalized report deliberately preserves unknown files. Phase 7C does not infer that `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, or `.PKG` extensions identify any universal PSP archive format.

## Embedded resource discovery

Files no larger than 64 MiB are scanned byte-by-byte with the shared resource detector layer.

For accepted embedded records:

- the exact parent disc path and byte offset are recorded;
- only bounded, extractable formats are physically carved;
- unbounded candidates such as conservatively recognized GIM/PMF records remain metadata-only when no complete extent can be proven;
- a recognized loose file is not redundantly reported as an embedded copy of itself;
- deterministic overlap suppression comes from the shared Phase 6D detector scan.

Files larger than the 64 MiB safety ceiling remain in the loose-file inventory. Phase 7C records a warning and skips the full embedded scan rather than loading an arbitrarily large resource into memory.

## Reports

### `metadata/game_resources.json`

Complete `GameResourceAnalysis`, including all loose resources, embedded records, and warnings.

### `metadata/embedded_resources.json`

A standalone deterministic list of embedded resource records, sorted by parent logical path, byte offset, and format.

### `reports/game_resources.csv`

Analyst-friendly loose-file inventory with:

```text
path,size,detected_format,kind,confidence,embedded_count,extracted_path,evidence
```

## Error boundaries

Game-level integrity failures remain fatal:

- unsafe traversal paths;
- symlink escapes from resource/project roots;
- unreadable ISO/CSO filesystem state required for extraction;
- failures that prevent deterministic output-root/report creation.

Resource-local failures remain non-fatal where possible:

- malformed known signatures;
- unsupported or unknown formats;
- oversized files skipped for embedded scanning;
- isolated file-read failures;
- isolated embedded extraction failures.

This keeps one malformed asset from preventing valid executable/module analysis or other resources from completing.

## Proprietary archive parser boundary

`game_resources.py` defines `ResourceContainerParser` and `ContainerInspection` as an extension boundary. The built-in parser registry is intentionally empty in Phase 7C.

This is deliberate: PSP games commonly use title-specific `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, and other containers, and the supplied upstream sources do not provide one universal parser for those formats. A parser should be added only when a real target game demonstrates a format with enough evidence to implement and test safely.

## Source/licensing boundary

- PPSSPP is used as a behavioral/reference source for PSP media/container conventions; GPL implementation code is not copied into this MIT core.
- pycdlib remains the optional ISO9660 dependency.
- maxcso remains a CSO/CISO format/reference source for the clean-room compressed-image layer.
- Rabbitizer/spimdisasm/Splat continue to own their established executable-analysis/project roles.
- Phase 6D and Phase 7C now share neutral format-signature logic through `resource_formats.py`.

## Python API

```python
from pspdisasm import analyze_game_resources, generate_game_project
```

`analyze_game_resources(source_name, output_dir, resources)` analyzes already-extracted `DiscResourceRecord` values.

`generate_game_project(...)` performs the complete Phase 7A → 7B → 7C pipeline automatically.

## Current limitations

Phase 7C does not yet:

- decrypt encrypted `~PSP` bodies;
- recursively unpack arbitrary proprietary game archives;
- transcode GIM/model/audio/video assets;
- claim exact file-to-code relationships without direct evidence;
- decode compressed `PT_PRXRELOC2` relocation streams;
- identify or reproduce the original PSP compiler/toolchain automatically.

The next archive-specific work should be driven by actual unknown containers encountered in a target PSP game rather than speculative parsers.