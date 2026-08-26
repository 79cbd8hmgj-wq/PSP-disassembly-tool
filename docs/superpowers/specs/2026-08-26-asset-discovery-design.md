# Phase 6D — Asset and Resource Discovery

Date: 2026-08-26
Status: Approved design checkpoint
Target branch: `phase6d-asset-discovery`

## Purpose

Phase 6D adds conservative asset and embedded-resource intelligence above the normalized PSP executable, disassembly, advanced-analysis, and Phase 6C data-typing layers. It should identify likely game resources embedded in decrypted ELF/PRX file-backed regions, describe them in machine-readable metadata, and connect them back to code/data references without pretending that uncertain format boundaries are exact.

This phase remains executable/module scoped. ISO/CSO filesystem orchestration and game-wide discovery remain a later major phase.

## Architectural boundary

The analyzer will be a new pure-analysis layer analogous to `data_typing.py`:

`ExecutableModel + DisassemblyResult + DataTypingResult + ElfImage -> AssetDiscoveryResult`

It must not mutate the ELF parser, disassembly result, Phase 6A advanced result, or Phase 6C typing result. The layer may consume their normalized records as evidence.

Project generation will run the asset-discovery pass after Phase 6C so resource references can use typed pointer/table/struct evidence.

## Supported first-pass formats

Detection is signature-driven but must include structural validation appropriate to each format. Phase 6D initially recognizes:

- PNG
- JPEG
- RIFF/WAV
- Sony GIM (`MIG.00.1PSP` family)
- Sony GMO where a stable identifying header is present
- PMF / PSP MPEG containers where the container signature and minimum header structure are valid
- VAG-family audio where the header is internally plausible
- ATRAC/AT3 when represented by a recognizable RIFF/WAVE container and codec tags that can be validated

Unknown or weakly recognized byte patterns are not emitted as assets merely because they resemble common magic values.

## Normalized models

Add the following records to `model.py`.

### `AssetRecord`

Fields:

- `address: int`
- `file_offset: int`
- `section: str`
- `format: str`
- `kind: str`
- `size: int | None`
- `confidence: float`
- `evidence: list[str]`
- `extractable: bool`
- `suggested_extension: str | None`
- `metadata: dict[str, object]`

`kind` is a broad user-facing class such as `image`, `audio`, `video`, `model`, or `container`.

### `AssetReferenceRecord`

Fields:

- `source_address: int`
- `asset_address: int`
- `source_function: str | None`
- `reference_kind: str`
- `asset_format: str`
- `confidence: float`
- `evidence: list[str]`

### `AssetDiscoveryResult`

Fields:

- `source_name: str`
- `assets: list[AssetRecord]`
- `references: list[AssetReferenceRecord]`
- `warnings: list[str]`

All records must serialize deterministically through dataclass/asdict-based project metadata.

## Scan domain

The analyzer scans only allocated, file-backed, non-executable ELF sections by default. It must:

- never scan `SHT_NOBITS` storage;
- never read beyond the section's file-backed bytes;
- use `ElfImage.vaddr_to_offset` only for addresses that are proven to map safely;
- retain exact virtual address and ELF file offset for every finding;
- avoid interpreting `.text` instruction streams as resource blobs in this phase.

A format detector may reject a candidate if its declared size crosses the containing section boundary.

## Detector contract

Each detector receives a bounded byte view, section information, virtual address, and file offset. It returns either no result or one validated asset candidate.

A detector must provide:

- normalized format name;
- broad asset kind;
- best-known size or `None`;
- confidence;
- evidence strings describing which checks passed;
- extraction safety flag;
- extension suggestion;
- optional parsed metadata.

### Confidence policy

Use conservative bands:

- `1.00`: exact container signature plus internally validated, bounded declared length/end marker;
- `0.95`: exact signature plus strong structural validation, but final extent requires a safe heuristic;
- `0.90`: exact PSP/resource signature and plausible bounded header, with unknown total size;
- below `0.90`: do not emit a first-class `AssetRecord` in Phase 6D.

Project extraction requires both `extractable=True` and a known positive size fully contained in the file-backed section.

## Format-specific validation

### PNG

Require the 8-byte PNG signature. Walk chunks using big-endian chunk lengths until a valid `IEND`; every chunk must stay within the section. Extractable only when `IEND` is reached cleanly.

### JPEG

Require SOI `FFD8`, then parse marker segments conservatively. A candidate becomes extractable only when a valid EOI `FFD9` is found without crossing the section. Embedded entropy-coded scan data must respect marker escaping/restart markers sufficiently to avoid treating arbitrary `FFD9` bytes as a guaranteed boundary.

### RIFF/WAV and ATRAC/AT3

Require `RIFF`, a bounded little-endian declared size, and a recognized form (`WAVE` for audio). Parse contained chunks within the declared RIFF extent. Record codec identifiers from `fmt ` where present. ATRAC/AT3 is a specialization of a valid RIFF/WAVE container, not a separate unbounded magic scan.

### GIM

Require the PSP GIM signature/header used by Sony GIM resources and enough header bytes to validate the family. If a trustworthy total length cannot be derived, emit a non-extractable record with known address/format rather than carving to the next candidate.

### GMO

Only emit GMO when a stable header/signature is present and bounded validation succeeds. If the repository/source evidence is insufficient to define a safe GMO detector, keep the detector omitted rather than guessing.

### PMF

Require a recognized PMF/PSMF-style signature plus plausible header fields. If a validated stream/container extent is derivable and bounded, extraction may be enabled; otherwise preserve the finding as non-extractable.

### VAG

Require the VAG header signature and internally plausible version/data-size/frequency fields. The declared payload must remain within the containing file-backed section before extraction is allowed.

## Candidate iteration and overlap

Scanning proceeds deterministically from low to high address in each eligible section.

- Candidate signatures may be found at any byte alignment because embedded files are not guaranteed to be word-aligned.
- Once an extractable, high-confidence asset with a validated size is accepted, the scanner may skip to its end for performance.
- Non-extractable candidates do not cause arbitrary skipping.
- Exact same-start conflicts use higher confidence, then a stable format-name lexical tie-break.
- A validated extractable asset outranks an overlapping weaker/non-extractable candidate.
- Two distinct validated contained assets are allowed when one is explicitly a subresource/container member only if the detector reports that relationship; otherwise overlapping first-class records are suppressed conservatively.

## Reference linking

Phase 6D links assets using existing normalized relationships; it does not invent new pointer interpretation rules.

An `AssetReferenceRecord` is emitted when:

1. an existing `ReferenceRecord.target_address` exactly matches an accepted asset start; or
2. a Phase 6C `TypedReferenceRecord.target_address` exactly matches an accepted asset start; or
3. a Phase 6C typed pointer/function-independent data object has `target_address` exactly equal to an accepted asset start.

Reference confidence is bounded by the asset confidence and the existing evidence confidence where one exists.

Deduplicate identical `(source_address, asset_address, reference_kind)` records while combining stable evidence strings.

This gives the project enough information to answer which functions/data locations reference a discovered resource without claiming semantic loader relationships that the code has not proved.

## Project integration

`ProjectArtifacts` gains:

- `asset_discovery_json: str`
- `asset_discovery: AssetDiscoveryResult`

`build_project_artifacts` runs `analyze_assets(model, result, data_typing, elf)` after Phase 6C.

`generate_project` writes:

- `metadata/asset_discovery.json` — complete result
- `metadata/assets.json` — asset records only
- `metadata/asset_references.json` — normalized references only
- `reports/assets.csv` — compact analyst-friendly inventory

The existing `assets/` directory becomes meaningful. Safe extractions are written under deterministic names:

`assets/<address>_<format>.<ext>`

For example:

`assets/0884A120_png.png`

If an asset is recognized but not safely bounded, no bytes are extracted; metadata still records it.

No Splat segment types are invented for assets in Phase 6D.

## CSV report

`reports/assets.csv` includes at minimum:

- address
- file_offset
- section
- format
- kind
- size
- confidence
- extractable
- reference_count
- suggested_extension

Rows are sorted by address then format.

## Public API and version

Expose:

`analyze_assets(model, disassembly, data_typing, elf) -> AssetDiscoveryResult`

from `pspdisasm` package root.

Bump package version from `0.8.0` to `0.9.0` when Phase 6D implementation lands.

## Error handling

Malformed candidate headers must never abort analysis of the executable. A detector rejects malformed candidates silently unless the condition indicates a genuine analyzer limitation worth surfacing. Warnings should be deterministic and reserved for analysis limitations, contradictory bounds, or unsupported-but-recognized cases rather than every false signature hit.

Project generation must not fail solely because no assets are discovered.

## Testing requirements

Add dedicated detector/unit coverage plus project-integration tests.

Required cases:

1. valid bounded PNG is detected and extractable;
2. PNG without bounded `IEND` is rejected or retained non-extractable according to detector contract, never over-read;
3. valid JPEG with EOI is detected;
4. invalid JPEG-like prefix is rejected;
5. valid RIFF/WAVE is detected with declared bounded size;
6. RIFF/ATRAC specialization records codec metadata when present;
7. out-of-section RIFF declared size is rejected;
8. valid bounded VAG is detected;
9. malformed VAG size/frequency is rejected;
10. GIM signature produces a conservative validated record;
11. PMF signature produces a conservative validated record;
12. executable and `SHT_NOBITS` sections are not scanned;
13. unaligned embedded signatures can be detected;
14. overlap resolution is deterministic;
15. existing direct reference to asset start becomes one asset reference;
16. typed reference to asset start is linked without mutating Phase 6C output;
17. unrelated pointer-looking integers do not become asset references;
18. duplicate reference evidence deduplicates deterministically;
19. `metadata/asset_discovery.json` is written;
20. `metadata/assets.json` is written;
21. `metadata/asset_references.json` is written;
22. `reports/assets.csv` is written and sorted;
23. only safely bounded assets are physically extracted;
24. recognized-but-unbounded assets are not physically carved;
25. existing Phase 1–6C tests remain green;
26. package root exports `analyze_assets` and reports version `0.9.0`.

## Non-goals for Phase 6D

Phase 6D does not:

- open ISO/CSO images;
- recursively scan PSP filesystem trees;
- decode textures/models/audio into editable source formats;
- infer arbitrary proprietary archive formats without validated signatures/structure;
- reconstruct game-specific resource manager semantics;
- rewrite Splat configs around asset boundaries;
- treat heuristic carving as verified extraction.

Those capabilities belong to later game-wide orchestration and format-specific extraction phases.

## Success criteria

Phase 6D is complete when a decrypted PSP ELF/PRX project generation pass can conservatively inventory recognized embedded resources, relate exact resource starts to existing code/data references, safely extract only bounded assets, produce deterministic metadata/reports, and pass the complete regression suite without weakening Phase 6C's conservative typing guarantees.
