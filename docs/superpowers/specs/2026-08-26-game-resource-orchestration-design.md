# Phase 7C — Game-wide resource orchestration design

## Status

Approved architectural continuation of Phase 7B. This phase adds whole-disc resource inventory and known-format discovery without claiming universal support for proprietary game archives.

## Goals

Phase 7C extends `game-project` so a PSP ISO/CSO produces a unified inventory of non-executable resources alongside the existing executable/module projects.

The implementation must:

- inspect every disc file classified as a resource;
- identify known resource formats from file content rather than extension alone;
- preserve unknown files instead of guessing their format;
- extract loose resource files beneath a containment-checked output root;
- recognize supported embedded resources inside loose files when safe boundaries can be proven;
- keep proprietary archive support behind a registry/plugin boundary;
- emit deterministic machine-readable and analyst-friendly reports;
- preserve Phase 7A/7B behavior and error boundaries.

## Non-goals

Phase 7C does not:

- implement PSP cryptographic decryption;
- claim that arbitrary `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, or `.PKG` files share one format;
- recursively decode unknown proprietary archives;
- transcode textures, models, audio, or video;
- infer file-to-code relationships without evidence;
- replace Phase 6D embedded-asset analysis inside ELF/PRX modules.

## Source boundaries

The implementation uses the supplied upstream projects only according to their established roles:

- PPSSPP is a behavioral/reference source for PSP media/container conventions such as PSMF, ATRAC, PBP/PSAR and runtime texture behavior. GPL code is not copied into the MIT core.
- pycdlib remains the optional ISO9660 traversal dependency used by the disc layer.
- maxcso remains the compressed-image format/reference source for the clean-room CSO reader.
- Phase 6D remains the authoritative embedded-resource detector for analyzed ELF storage.

No supplied source provides a universal parser for game-specific archive formats, so Phase 7C must explicitly preserve unknown containers and expose an extension point rather than inventing decoding rules.

## Architecture

### 1. Shared resource signatures

Create `src/pspdisasm/resource_formats.py` containing format detectors that operate on arbitrary byte spans. The initial detector set is the conservative subset already implemented in Phase 6D:

- PNG
- JPEG
- RIFF/WAVE
- ATRAC-family RIFF (`.at3`)
- VAG
- GIM
- PSMF/PMF

The shared detector returns a neutral `ResourceFormatMatch` rather than an ELF-specific `AssetRecord`.

`asset_discovery.py` adapts those matches back into `AssetRecord` objects, preserving Phase 6D behavior while eliminating duplicate format logic.

### 2. Disc resource extraction

Extend the disc layer with a narrow extraction primitive for non-executable files. Phase 7A currently extracts only boot/module candidates. Phase 7C will extract resource candidates under:

```text
<output>/resources/files/<logical-disc-path>
```

All paths use the existing containment rules. Traversal or symlink escapes remain fatal integrity errors.

Metadata files remain metadata and are not duplicated into the resource tree unless they are explicitly classified as resources in the future.

### 3. Game-resource model

Create `src/pspdisasm/game_resources.py` with dedicated dataclasses rather than reusing ELF-addressed `AssetRecord`:

- `GameResourceRecord`
  - logical disc path
  - extracted path
  - size
  - detected format
  - kind (`image`, `audio`, `video`, `container`, `unknown`)
  - confidence
  - evidence
  - extension hint
  - metadata
  - embedded resource count
- `EmbeddedGameResourceRecord`
  - parent disc path
  - file offset
  - detected format/kind
  - size when bounded
  - confidence/evidence
  - extraction path when safe
- `GameResourceAnalysis`
  - source image identity
  - resource records
  - embedded records
  - unknown-file count
  - warnings

Loose-file classification examines a bounded prefix/full file as appropriate. A format match at offset zero is treated as the file format. Files without an accepted match remain `unknown`.

### 4. Embedded scanning

Known detectors may scan inside loose resource files only under conservative limits:

- scanning is byte-granular;
- only accepted confidence >= 0.90 records are reported;
- bounded formats may be physically extracted;
- unbounded GIM/PMF candidates remain metadata-only unless the detector can prove an extent;
- accepted bounded resources advance the cursor by their size to suppress overlapping weaker candidates;
- files above a configured safety ceiling are streamed/read with an explicit maximum rather than blindly loaded into memory.

The initial implementation will use a fixed conservative scan ceiling suitable for testability. Large files that exceed it remain inventoried and receive a warning rather than exhausting memory.

### 5. Archive/parser registry

Define a minimal internal registry interface:

```python
class ResourceContainerParser(Protocol):
    name: str
    def probe(prefix: bytes, path: str) -> float: ...
    def inspect(path: Path) -> ContainerInspection: ...
```

Phase 7C ships no speculative proprietary game parser. The registry exists so later game-specific formats can be added without changing orchestration or report schemas.

Standard PSP containers may be added later through the same interface when their exact scope is justified by real inputs.

### 6. Game-project integration

`generate_game_project()` continues to own whole-game orchestration.

After Phase 7A disc scan and module processing, it invokes the game-resource scanner over every `DiscFileRecord` with classification `resource`.

Outputs:

```text
<output>/
├── metadata/
│   ├── disc.json
│   ├── game_analysis.json
│   ├── module_links.json
│   ├── propagated_symbols.json
│   ├── game_resources.json
│   └── embedded_resources.json
├── reports/
│   └── game_resources.csv
├── resources/
│   ├── files/<logical-disc-path>
│   └── embedded/<logical-disc-path>/<offset>_<format>.<ext>
└── projects/...
```

`GameProjectResult` gains resource counters and paths without changing existing fields.

### 7. CLI behavior

`pspdisasm game-project INPUT OUTPUT` automatically performs Phase 7C. No second command is required.

CLI summary adds:

- resource files inventoried;
- known-format files;
- unknown files;
- embedded resources discovered.

The lightweight `pspdisasm game` command remains Phase 7A inventory/executable extraction only.

## Error handling

Fatal game-level errors:

- unsafe output paths / containment violations;
- unreadable disc image or ISO filesystem;
- unavailable mandatory disc backend;
- output-root creation failures that prevent deterministic reporting.

Non-fatal resource-local errors:

- malformed known-format candidate;
- resource file read failure after disc inventory;
- oversized file skipped for embedded scanning;
- unsupported/unknown container;
- failed bounded embedded extraction.

Resource-local failures are recorded as warnings so one bad asset does not abort executable analysis or other resource discovery.

## Determinism

All records are sorted by normalized logical disc path, then embedded file offset, then format. JSON uses sorted keys and CSV uses the same order. No timestamps or environment-dependent absolute paths are written into normalized metadata.

## Testing

Synthetic tests will cover:

1. loose PNG/AT3/PMF detection from ISO resources;
2. unknown resource preservation;
3. extraction beneath `resources/files/`;
4. embedded resource discovery and bounded extraction;
5. oversized resource scan warning/skip behavior;
6. malformed resource isolation;
7. traversal/symlink containment remaining fatal;
8. Phase 6D detector parity after extracting shared format logic;
9. `game-project` CLI counters and report creation;
10. legacy Phase 7A/7B tests remaining green.

## Success criteria

Phase 7C is complete when a synthetic PSP ISO/CSO can be passed to `game-project` and the resulting workspace contains deterministic module analysis plus a safe whole-disc resource inventory, known-format classification, conservative embedded-resource discovery, unknown-file preservation, and an extension boundary for later proprietary archive parsers.