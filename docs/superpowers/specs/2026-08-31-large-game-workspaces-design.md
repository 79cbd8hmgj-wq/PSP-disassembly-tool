# Phase 8A — Large game workspaces design

## Status

Approved follow-on infrastructure phase after the completed Phase 7A–7G PSP analysis pipeline. This phase solves the practical size boundary exposed by retail PSP images and extracted game payloads that are too large to store in GitHub or transfer through chat-based workflows.

The design is intentionally condensed into three implementation tasks. Large copyrighted/runtime payloads remain external; GitHub stores only tooling, manifests, deterministic metadata, synthetic fixtures, and documentation.

## Goals

Phase 8A must make the toolkit practical for large real PSP games without weakening the existing whole-game analysis pipeline.

The implementation must:

- accept an ISO/CSO or already-extracted game directory as a local workspace source;
- keep original game payloads outside repository-managed outputs by default;
- generate deterministic file manifests containing logical path, size, SHA-256, type/classification, and analysis state;
- preserve enough provenance to prove that exported analysis evidence came from a specific local source file;
- support resumable analysis so unchanged files are not repeatedly re-read or reprocessed unnecessarily;
- export small, deterministic analysis packs containing only the evidence required for a selected module/function/resource investigation;
- add CLI commands for preparing, analyzing, and exporting workspaces;
- prevent accidental repository inclusion of ISOs, CSOs, retail binaries, large extracted trees, save states, and raw runtime dumps;
- preserve current `game-project` behavior for callers that do not use the new workspace commands.

## Non-goals

Phase 8A does not:

- upload or host retail PSP images or extracted copyrighted payloads;
- replace the existing Phase 7 disc/module/resource analyzers;
- create a remote binary-storage service;
- require Git LFS for game payloads;
- infer or recover missing retail files;
- add title-specific archive parsers;
- add PSP executable decryption/decompression;
- make analysis packs self-sufficient replacements for the user's original game when a future operation needs bytes outside the exported evidence set.

## Task 1 — Local workspace and deterministic manifest

Add a focused workspace layer that references a local source rather than copying the entire source into the repository-facing project tree.

### Workspace model

A prepared workspace contains small metadata plus generated analysis output, for example:

```text
workspace/
├── workspace.json
├── manifests/
│   └── files.json
├── analysis/
├── packs/
└── cache/
```

The manifest records each source file with at least:

- normalized PSP/logical path;
- byte size;
- SHA-256;
- source kind (`iso`, `cso`, or extracted directory);
- detected/known role when available (`executable`, `resource`, `unknown`, etc.);
- analysis state/version;
- references to generated metadata rather than copied retail bytes.

Absolute host paths must not be emitted into portable manifest/report files. A workspace may store the local source locator in a dedicated machine-local field/file that is excluded from analysis packs and clearly marked non-portable.

### Determinism

For the same source bytes and toolkit version/configuration, portable workspace metadata must be stable:

- normalized forward-slash paths;
- deterministic ordering;
- no timestamps in identity-bearing portable metadata;
- SHA-256 used for content identity;
- schema/tool version recorded explicitly.

### Resume/caching

Analysis state is keyed by input content hash plus the relevant analysis/config version. If the content identity and analysis inputs are unchanged, the toolkit may reuse previous deterministic results. If any identity-bearing input changes, affected cached analysis must be invalidated rather than silently reused.

## Task 2 — Selective analysis packs and workspace commands

Expose a small CLI surface around the workspace layer:

```text
pspdisasm prepare-game <game.iso|game.cso|extracted-dir> <workspace>
pspdisasm analyze-workspace <workspace>
pspdisasm make-pack <workspace> [selectors...] --output <pack.zip>
```

The exact parser wiring should reuse the current Phase 7 analyzers instead of duplicating disc/module/resource logic.

### `prepare-game`

- validates the source;
- enumerates its logical filesystem using the existing ISO/CSO/extracted-file handling where applicable;
- hashes files in a streaming/bounded-memory manner;
- writes the deterministic workspace manifest;
- does not copy the full retail payload into the portable workspace.

### `analyze-workspace`

- drives the existing whole-game analysis against the local source referenced by the workspace;
- writes deterministic analysis metadata beneath the workspace;
- records per-file/module analysis state;
- reuses valid previous results when possible;
- isolates ordinary per-resource/module analysis failures according to existing Phase 7 semantics.

### `make-pack`

Analysis packs are small transferable evidence bundles, not miniature game copies.

Selectors should support the useful initial cases without over-generalizing:

- one executable/module by logical path or module identity;
- one function/address when function metadata exists;
- one resource/container path;
- optional dependency/context inclusion bounded by explicit limits.

A pack may include:

- selected module/function byte slices when required;
- disassembly/function metadata;
- symbol/import/export/relocation evidence;
- relevant call/reference information;
- selected `.rodata`/`.data` slices referenced by the target;
- selected resource/container headers or bounded entry samples;
- source logical paths, offsets, sizes, and SHA-256 provenance;
- a deterministic `pack-manifest.json` describing every included artifact.

The default must favor the minimum sufficient evidence. Full source files are included only when explicitly selected and allowed by a conservative pack-size policy.

Pack generation must reject unsafe output paths, traversal, symlink escapes, and inconsistent provenance.

## Task 3 — Repository safety and hardening

### Repository guards

Expand `.gitignore` and add an automated repository-content guard that fails CI for newly tracked payload categories or files exceeding a conservative threshold unless explicitly allowlisted for small synthetic fixtures.

Guarded categories include at minimum:

- `*.iso`, `*.cso`, `*.zso`, `*.dax`;
- PPSSPP save states and raw memory dumps;
- user workspace payload/cache directories;
- extracted retail-game trees;
- oversized opaque binaries.

The guard must inspect tracked content, not merely rely on `.gitignore`.

### Safety and scale hardening

Tests must cover:

- a synthetic multi-file PSP-like tree large enough to exercise streaming/resume behavior without committing commercial data;
- deterministic manifest output independent of absolute workspace/source location;
- changed-file cache invalidation;
- unchanged-file resume behavior;
- analysis-pack determinism;
- bounded pack extraction/export paths;
- traversal/symlink containment;
- size-policy enforcement;
- repository guard behavior;
- legacy Phase 7 workflows remaining green.

No real retail ISO, commercial game payload, save state, or raw runtime dump is added to the toolkit repository.

## Architecture boundaries

Phase 8A is an orchestration/storage-boundary feature, not a replacement analysis engine.

Preferred module boundaries are:

- `workspace` layer: schema, manifest, source identity, state/cache decisions;
- existing Phase 7 analyzers: disc/module/resource analysis;
- `analysis_pack` layer: deterministic evidence selection and export;
- repository guard: standalone CI/check helper with explicit allowlist rules.

The workspace layer must call existing public APIs where possible. If a small internal refactor is required to analyze files without copying them into a repository-facing project tree, that refactor should preserve current APIs and behavior.

## Error handling

Fatal workspace/integrity failures include:

- missing or unreadable declared source;
- workspace schema/version mismatch that cannot be migrated safely;
- source content no longer matching an identity required by the requested operation;
- output traversal or symlink escape;
- corrupt pack manifest/provenance;
- failure to write deterministic required metadata transactionally.

Ordinary analysis-local failures retain existing Phase 7 behavior and are reported per module/resource without corrupting the workspace state.

Interrupted preparation/analysis must not leave a completed manifest/state marker for incomplete work. Write required metadata transactionally via temporary files followed by atomic replacement where practical.

## Compatibility

Existing commands such as `game-project` remain supported and do not require a workspace. Phase 8A adds a scalable path for large real-game work rather than breaking the direct-input workflow.

Public Python APIs should expose the core workspace and pack primitives once their schemas are stable, while filesystem-location details remain implementation-specific.

## Success criteria

Phase 8A is complete when a user can keep a full PSP ISO/CSO or extracted game only on their local machine, prepare a deterministic workspace without committing/copying the full payload into GitHub-facing artifacts, resume whole-game analysis safely, and export a small provenance-locked analysis pack for a selected module/function/resource that can be transferred independently.

The repository must actively reject accidental large/runtime payload additions, all Phase 8A tests must pass using synthetic fixtures, and the pre-existing Phase 7 test suite must remain green.
