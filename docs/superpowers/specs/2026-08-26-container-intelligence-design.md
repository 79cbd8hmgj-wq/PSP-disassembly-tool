# Phase 7D — Proprietary container intelligence design

## Status

Approved continuation of Phase 7C. This phase adds deterministic intelligence and safe parser orchestration for unknown game-resource containers without inventing universal rules for `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, or similar extensions.

## Goals

Phase 7D turns Phase 7C's preserved `unknown` files into actionable reverse-engineering targets.

The implementation must:

- fingerprint every unknown loose resource deterministically;
- group similar unknown files into reproducible candidate families;
- retain extension, prefix, entropy, size, and embedded-resource evidence without treating any one signal as proof of a format;
- provide a typed parser interface that can be supplied programmatically;
- select parsers deterministically from explicit probe confidence;
- inspect and extract only entries whose offsets and sizes are proven to stay inside the parent file;
- preserve entry provenance from disc path through container path and byte range;
- classify extracted entries with the shared Phase 6D/7C resource detectors;
- isolate parser-local failures while keeping containment violations fatal;
- emit deterministic JSON/CSV reports;
- preserve Phase 7A–7C behavior when no container parsers are supplied.

## Non-goals

Phase 7D does not:

- claim an extension identifies a universal archive format;
- ship speculative parsers for title-specific formats without a real sample/specification;
- decrypt encrypted PSP executable bodies;
- decompress arbitrary unknown codecs;
- infer semantic names for anonymous archive entries;
- execute code from disc contents;
- recursively unpack without strict depth, entry-count, and byte-bound checks.

## Architecture

### 1. Container intelligence module

Create `src/pspdisasm/resource_containers.py` with focused, format-neutral types and helpers:

- `ContainerCandidateProfile`
  - logical path;
  - size;
  - lowercase suffix;
  - first 16 bytes as hex;
  - printable ASCII view of the prefix;
  - Shannon entropy over a bounded sample;
  - embedded-resource count;
  - bounded embedded bytes when known;
  - deterministic family key.
- `ContainerFamily`
  - family key;
  - member paths;
  - member count;
  - total size;
  - shared suffix/prefix fingerprint.
- `ContainerEntry`
  - logical inner path;
  - byte offset;
  - byte size;
  - optional metadata.
- `ContainerInspection`
  - parser name;
  - format name;
  - confidence;
  - entries;
  - warnings.
- `ResourceContainerParser` protocol
  - `name: str`
  - `probe(prefix: bytes, path: str) -> float`
  - `inspect(path: Path) -> ContainerInspection`

The module also owns deterministic parser selection and profile/family helpers.

### 2. Candidate profiling

Every Phase 7C loose resource that remains `unknown` receives a `ContainerCandidateProfile`.

Profiling is deliberately descriptive, not classificatory:

- suffix is a hint only;
- prefix bytes are recorded exactly;
- entropy is calculated over at most 64 KiB;
- existing embedded-resource evidence is attached;
- `family_key` groups files by normalized suffix plus the first four bytes of content.

No profile field changes the resource's `detected_format` from `unknown`.

### 3. Parser selection

`analyze_game_resources()` gains an optional `container_parsers` iterable. The default remains empty.

For each unknown file:

1. call each parser's `probe()` with the same bounded prefix and logical path;
2. clamp/reject non-finite or out-of-range values;
3. accept only confidence `>= 0.90`;
4. choose the highest confidence;
5. resolve equal confidence by parser name, then input order.

Probe failures are recorded as resource-local warnings and do not abort the game.

### 4. Entry validation and extraction

A selected parser may return entries, but the orchestrator does not trust them blindly.

Each entry must satisfy:

- non-empty relative POSIX path;
- no absolute path and no `..` component;
- `offset >= 0`;
- `size > 0`;
- `offset + size <= parent_size`;
- total accepted entry count does not exceed 4096 per container.

Accepted entries are written beneath:

```text
resources/containers/<parent-logical-path>/<entry-logical-path>
```

The same containment checks used elsewhere in the project remain authoritative. Traversal or symlink escape is fatal because it violates workspace integrity.

Invalid range/path entries are rejected from extraction and recorded as parser-local warnings rather than silently truncated.

### 5. Extracted-entry classification

Each extracted entry is classified with `detect_resource_at(..., 0)` using the shared detector layer. Known PNG/JPEG/WAV/AT3/VAG/GIM/PMF entries therefore inherit the same evidence/confidence semantics as loose files.

Unknown extracted entries remain unknown. Phase 7D does not recursively inspect nested containers yet; recursion is deferred until a real format demonstrates a need for it and a safe depth/byte budget can be specified from evidence.

### 6. Game-resource model integration

Extend `GameResourceAnalysis` with:

- `container_candidates`;
- `container_families`;
- `container_inspections`;
- `container_entries`.

Extend each unknown `GameResourceRecord` with optional parser/family fields without changing known-resource behavior.

### 7. Reports

Phase 7D adds:

```text
metadata/container_candidates.json
metadata/container_inspections.json
reports/container_candidates.csv
reports/container_entries.csv
resources/containers/...
```

Records are sorted deterministically by logical path, parser name, entry offset, and inner path as appropriate. No timestamps or absolute host paths are emitted.

### 8. Game-project and API integration

`generate_game_project()` gains optional `container_parsers=()` and forwards them to `analyze_game_resources()`.

`GameProjectResult` gains:

- `container_candidate_count`;
- `container_inspection_count`;
- `container_entry_count`;
- `containers_path`.

The CLI continues to use the empty built-in parser set. It can still report unknown-container candidate/family counts; custom parser loading from arbitrary Python modules is intentionally out of scope for this phase.

Public API exports include the parser/entry/inspection types so callers can provide title-specific parsers safely.

## Error handling

Fatal integrity failures:

- unsafe extracted resource path;
- unsafe container entry destination path;
- symlink escape from the project root;
- failures preventing deterministic output/report creation.

Resource/parser-local failures:

- parser `probe()` exception;
- parser `inspect()` exception;
- malformed entry range;
- too many entries;
- entry extraction/read error after containment validation;
- unsupported extracted entry format.

Local failures are warnings and analysis continues.

## Testing

Synthetic tests cover:

1. deterministic unknown-file fingerprinting and family grouping;
2. parser confidence threshold and deterministic tie-breaking;
3. parser probe failure isolation;
4. bounded entry extraction and shared-format classification;
5. out-of-bounds entry rejection without truncation;
6. traversal entry path rejection as an integrity failure;
7. deterministic JSON/CSV output;
8. `game-project` result counters;
9. no-parser behavior preserving Phase 7C semantics;
10. all legacy tests remaining green.

## Success criteria

Phase 7D is complete when a whole-game project can identify repeat families of unknown resource files, record useful deterministic reverse-engineering fingerprints, accept an evidence-backed title-specific parser through the Python API, safely inspect/extract bounded entries with provenance, classify extracted supported resources, and report the results without claiming unsupported proprietary formats.