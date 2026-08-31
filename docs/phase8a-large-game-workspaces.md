# Phase 8A — Large Game Workspaces

Phase 8A adds a scalable workflow for PSP games whose ISO/CSO images or extracted payloads are too large to keep in GitHub or transfer through chat-based reverse-engineering workflows.

The original game remains on the user's machine. The toolkit stores deterministic portable metadata, resumable analysis output, and optional bounded analysis packs.

## Commands

Prepare a local workspace from an ISO, CSO, or extracted PSP directory:

```bash
pspdisasm prepare-game /path/to/game.iso /path/to/game-workspace
```

or:

```bash
pspdisasm prepare-game /path/to/extracted-game /path/to/game-workspace
```

Run or resume whole-game analysis:

```bash
pspdisasm analyze-workspace /path/to/game-workspace
```

NID databases remain repeatable exactly as they are for `game-project`:

```bash
pspdisasm analyze-workspace /path/to/game-workspace \
  --nid-db psp_nids.json \
  --nid-db title_nids.csv
```

Create a portable module evidence pack:

```bash
pspdisasm make-pack /path/to/game-workspace \
  --module PSP_GAME/SYSDIR/EBOOT.BIN \
  --output eboot-analysis.zip
```

Create a function evidence pack with an explicit module:

```bash
pspdisasm make-pack /path/to/game-workspace \
  --module PSP_GAME/SYSDIR/EBOOT.BIN \
  --function 0x08804000 \
  --output function-analysis.zip
```

When exactly one analyzed module is available, `--module` may be omitted:

```bash
pspdisasm make-pack /path/to/game-workspace \
  --function 0x08804000 \
  --output function-analysis.zip
```

Create a resource evidence pack:

```bash
pspdisasm make-pack /path/to/game-workspace \
  --resource PSP_GAME/USRDIR/example.dat \
  --output resource-analysis.zip
```

Existing direct workflows such as `pspdisasm game-project game.iso output/` remain supported. `game-project` also accepts an already-extracted PSP directory directly.

## Workspace layout

A prepared workspace uses small portable metadata alongside generated analysis:

```text
workspace/
├── workspace.json
├── .pspdisasm-local.json
├── manifests/
│   └── files.json
├── analysis/
│   ├── state.json
│   └── game_project/
├── cache/
└── packs/
```

`workspace.json` and `manifests/files.json` are portable. They do not contain the absolute host path to the user's game.

`.pspdisasm-local.json` is deliberately machine-local. It records the absolute source locator and a lightweight source snapshot needed to detect changes before cached analysis is reused. It must not be copied into portable evidence or committed to source control.

## Deterministic file identity

Every source file is represented by a `WorkspaceFileRecord` containing:

- normalized PSP/logical path;
- byte size;
- SHA-256;
- source kind;
- classification;
- executable kind when known;
- analysis state and analysis schema version.

`source_identity` is a SHA-256 over the canonical ordered file identities. It is independent of the source's absolute host path, so byte-identical extracted trees prepared in different locations produce the same portable identity.

All large source hashing is streamed in bounded chunks. Preparing an ISO/CSO does not require extracting the complete disc tree merely to calculate the workspace manifest.

## Resume behavior

`analyze-workspace` computes an analysis key from:

- workspace `source_identity`;
- analysis schema version;
- the currently installed toolkit version;
- the content identities of supplied NID databases.

When that key matches `analysis/state.json` and the required whole-game analysis output is present, the previous result is reused.

The machine-local source snapshot is validated before reuse. If the source changes, analysis is refused with an instruction to run `prepare-game` again rather than silently trusting stale metadata.

A completed `analysis/state.json` is written only after successful whole-game analysis. Interrupted or failed analysis therefore does not create a false completed-state marker. Installing a different toolkit version changes the analysis key and forces regeneration instead of reusing stale results.

## Extracted directory support

Phase 8A accepts an already-extracted PSP filesystem in addition to ISO/CSO input.

Directory preparation and whole-game analysis walk regular files only and reject symlinks. The Phase 7 game-project path dispatches directly to directory-specific scan and resource-copy helpers, preserving the original logical path casing. Executable candidates are mirrored beneath `modules/<logical-path>` and resource files are streamed beneath `resources/files/<logical-path>` before the established Phase 7 module/resource analyzers run.

ISO/CSO behavior remains on the existing disc-image path. Directory support therefore shares the same downstream Phase 7 analysis implementation without creating or depending on a temporary ISO.

## Analysis packs

Analysis packs are deterministic ZIP files designed to transfer only the evidence needed for one reverse-engineering target.

Supported initial selectors are:

- a module by exact logical path;
- a function by exact function name or address, optionally paired with a module selector for disambiguation;
- a resource by exact logical path.

A function selector without `--module` is accepted only when exactly one analyzed module is available. Otherwise the module must be supplied explicitly.

A pack contains a deterministic `pack-manifest.json` with:

- workspace source identity;
- selector kind/value;
- selected source logical path, size, and SHA-256;
- every included artifact path, size, and SHA-256.

The ZIP writer uses fixed metadata and deterministic member ordering. Repeating the same pack operation against the same workspace produces byte-identical output.

### Module packs

Module packs may include:

- normalized module record;
- executable metadata;
- disassembly;
- advanced analysis;
- data typing;
- asset discovery;
- functions, symbols, references, and strings;
- selected module bytes when they fit within the pack budget.

Generated JSON is portableized before export so machine-local workspace paths are not leaked. The complete parent module is always provenance-verified by streamed size/SHA-256 checks even when it is too large to include in the ZIP.

### Function packs

Function packs include only the selected function's useful neighborhood:

- function metadata;
- instructions;
- references touching the function range;
- matching call-graph evidence when available;
- a bounded byte context mapped through executable section metadata;
- parent module SHA-256 and slice offset provenance.

Large parent modules are not loaded wholesale merely to produce a function pack. The parent is verified by streamed SHA-256 and only the bounded function context is read into the pack.

### Resource packs

Resource packs include:

- the normalized resource record;
- a bounded leading sample;
- the complete selected resource only when it fits the configured pack budget;
- related embedded-resource/container records when available.

The complete parent resource is provenance-verified by streamed size/SHA-256 checks. If the resource is larger than the pack budget, the bounded sample can still be exported without reading or embedding the full file in memory.

## Pack limits and containment

The default maximum uncompressed evidence budget is 16 MiB. The default context window is 4096 bytes.

Both are configurable with:

```text
--max-bytes N
--context-bytes N
```

Pack generation fails before leaving a completed output when required evidence plus the manifest would exceed the budget. Optional full module/resource payloads are omitted when necessary to preserve the configured bound.

Logical selectors reject absolute paths and `..` traversal. Analysis paths are contained beneath the generated game-project root. Pack output paths reject symlink components so a requested destination cannot silently escape through a symlink.

## Repository payload guard

Phase 8A adds `tools/check_repository_payloads.py` and runs it in GitHub Actions before pytest.

The guard inspects **tracked Git content**, not merely `.gitignore` rules.

It rejects at least:

- `.iso`, `.cso`, `.zso`, `.dax` disc images;
- `.ppst`, `.savestate`, and `.memdump` runtime artifacts;
- generated workspace/cache/resource payload trees;
- oversized opaque game binaries over the 16 MiB repository threshold.

Small synthetic fixtures beneath `tests/fixtures/` may be allowlisted by policy. Commercial game/runtime data is not.

`.gitignore` additionally prevents common local PSP images, PPSSPP states, workspace-local state, caches, and pack outputs from being added accidentally.

## Limitations

Phase 8A does not:

- upload or remotely host the original game;
- make Git LFS a game-storage requirement;
- recover missing retail files;
- decrypt encrypted PSP executables;
- decompress unsupported PSP executable formats;
- add title-specific proprietary archive parsers;
- make a small analysis pack a replacement for the original game when later analysis needs bytes outside that pack.

The large-file boundary is deliberately architectural: the game stays local, while deterministic evidence travels.
