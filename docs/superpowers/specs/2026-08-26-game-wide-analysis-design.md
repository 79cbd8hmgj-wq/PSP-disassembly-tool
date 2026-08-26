# Phase 7B — Game-Wide Module Analysis Design

## Purpose

Phase 7B consumes the Phase 7A disc manifest and extracted executable candidates, automatically analyzes every usable decrypted PSP module, generates a separate decompilation workspace for each analyzable module, links imports and exports across the game, and emits one deterministic game-level analysis manifest.

Phase 7B does not add new executable-analysis heuristics. It orchestrates the existing Phase 1–6 analyzers around the whole-disc intake added in Phase 7A.

## User-facing workflow

Phase 7A remains available as the lightweight inventory command:

```bash
pspdisasm game GAME.iso game_intake
```

Phase 7B adds a distinct full-analysis command:

```bash
pspdisasm game-project GAME.iso game_decomp
```

Optional NID databases are accepted exactly like the existing `project` and `link` commands:

```bash
pspdisasm game-project GAME.cso game_decomp \
  --nid-db psp_nids.csv \
  --nid-db game_specific_nids.json
```

Keeping `game` scan-only preserves Phase 7A behavior and gives analysts a cheap inventory operation. `game-project` owns the heavier automatic analysis workflow.

## Architecture

Add one orchestration module, `src/pspdisasm/game_project.py`. It composes existing public/internal capabilities rather than duplicating them:

1. `scan_game_disc()` inventories the ISO/CSO and extracts boot/module candidates.
2. Each extracted candidate is passed through `analyze_file()`.
3. Candidates requiring PSP decryption are retained as unresolved module records and are not passed to the disassembler or Splat project generator.
4. Decrypted ELF/PRX candidates are passed through `disassemble_file()` and `generate_project()`.
5. Successfully analyzed decrypted modules become `ModuleAnalysisInput` records.
6. `link_modules()` runs once over the complete successfully analyzed module set, using the merged optional NID database.
7. Deterministic game-level JSON reports summarize module status, module links, propagated symbols, warnings, and output locations.

The first implementation intentionally favors reuse over eliminating repeated parsing inside `generate_project()`. The duplicated per-module parsing is bounded, keeps Phase 3 generation unchanged, and avoids a broad project-writer refactor in the same phase. A later performance pass can introduce artifact reuse if profiling shows it matters.

## Data model

`game_project.py` defines the following normalized records.

### `GameModuleAnalysisRecord`

Fields:

- `path: str` — logical disc path from the Phase 7A manifest.
- `extracted_path: str | None` — path relative to the game project root.
- `executable_kind: str` — Phase 7A kind (`elf`, `psp_container`, or `unknown`).
- `is_boot: bool` — whether Phase 7A selected this module as the boot executable.
- `status: str` — one of `analyzed`, `needs_decryption`, or `failed`.
- `module_name: str | None` — normalized PSP module name when available.
- `project_path: str | None` — per-module Splat workspace relative to the game root.
- `function_count: int` — zero when disassembly did not run.
- `symbol_count: int` — zero when disassembly did not run.
- `reference_count: int` — zero when disassembly did not run.
- `string_count: int` — zero when disassembly did not run.
- `warnings: list[str]` — deterministic module-local warnings or failure explanation.

### `GameProjectAnalysis`

Fields:

- `source_name: str`
- `title: str | None`
- `disc_id: str | None`
- `image_format: str`
- `boot_path: str | None`
- `modules: list[GameModuleAnalysisRecord]`
- `links: ModuleLinkAnalysis`
- `warnings: list[str]`

### `GameProjectResult`

Fields:

- `output_dir: Path`
- `analysis_path: Path`
- `links_path: Path`
- `module_count: int`
- `analyzed_count: int`
- `needs_decryption_count: int`
- `failed_count: int`

## Deterministic output layout

```text
game_decomp/
├── metadata/
│   ├── disc.json
│   ├── param_sfo.json
│   ├── game_analysis.json
│   ├── module_links.json
│   └── propagated_symbols.json
├── modules/
│   └── PSP_GAME/...                # Phase 7A extracted inputs
└── projects/
    └── PSP_GAME/
        ├── SYSDIR/
        │   └── EBOOT.BIN/          # normal single-module Splat workspace
        └── USRDIR/
            └── PLUGIN.PRX/
```

Per-module project directories mirror the logical disc path under `projects/`. This avoids basename collisions and preserves provenance without inventing opaque identifiers. Path construction must use the same containment discipline as Phase 7A and reject absolute or parent-traversal components.

`metadata/game_analysis.json` contains the full `GameProjectAnalysis` object.

`metadata/module_links.json` contains the normalized `ModuleLinkAnalysis` object produced from all successfully analyzed decrypted modules.

`metadata/propagated_symbols.json` contains only `ModuleLinkAnalysis.propagated_symbols` for convenient downstream consumption.

## Module processing rules

Process Phase 7A module records in deterministic case-insensitive path order.

For each module:

1. Require `output_path` from the Phase 7A extraction result. Missing output paths become `failed` records rather than crashing the entire game analysis.
2. Resolve the extracted path under the game output root and reject any path that escapes that root.
3. Run `analyze_file()`.
4. If `model.needs_decryption` is true:
   - record `status="needs_decryption"`;
   - preserve container/module metadata and warnings;
   - do not disassemble;
   - do not create a per-module Splat project;
   - do not include the module in cross-module linking.
5. Otherwise run `disassemble_file()`.
6. Generate the per-module Splat project under the mirrored `projects/` path, passing the same `--nid-db` list supplied to `game-project`.
7. Record analysis counts and include the module in the global linker input.

A malformed or unsupported non-boot module must not abort analysis of other modules. It becomes `status="failed"` with a deterministic warning. The selected boot executable is not treated specially for error propagation: Phase 7A already guarantees that a recognizable boot candidate exists, but Phase 7B may still record it as encrypted or failed.

## Cross-module linking

After all modules have been processed, load the optional NID databases once with `load_nid_databases()` and call `link_modules()` over the successfully analyzed decrypted modules.

The existing linker rules remain authoritative:

- exact `(library, kind, NID)` identity;
- unique-provider links only;
- ambiguous providers produce warnings instead of guessed links;
- external NID names take precedence when strong;
- meaningful unique-provider local names may propagate with confidence `0.95`;
- autogenerated names are not treated as authoritative local names.

No new NID heuristics are introduced in Phase 7B.

## Error handling

Fatal errors are limited to failures that prevent game-level orchestration itself, including:

- unreadable ISO/CSO input;
- invalid Phase 7A filesystem structure;
- inability to create/write the game output root;
- invalid traversal/containment paths.

Per-module parse, disassembly, and project-generation errors are isolated to that module and recorded as `failed`, allowing remaining modules to continue.

`EngineUnavailableError` from missing global requirements such as the Phase 2 analysis engines remains fatal because the requested full-analysis workflow cannot be performed correctly without the configured engine set.

## CLI behavior

Add:

```text
pspdisasm game-project INPUT OUTPUT [--nid-db FILE ...]
```

Successful summary output includes:

- game title or `<unknown>`;
- disc ID when known;
- total executable candidates;
- successfully analyzed modules;
- modules needing decryption;
- failed modules;
- cross-module link count;
- `metadata/game_analysis.json` path.

Exit code remains `0` when orchestration succeeds even if individual modules are encrypted or fail analysis; those conditions are explicit records in the output. Fatal orchestration errors use the existing CLI error path and exit code `2`.

## Public Python API

Export:

```python
from pspdisasm import generate_game_project
```

Signature:

```python
def generate_game_project(
    source: Path | str,
    output_dir: Path | str,
    *,
    nid_databases: Iterable[Path | str] = (),
) -> GameProjectResult:
    ...
```

The detailed normalized analysis remains persisted in JSON; callers needing it in-memory may use the private orchestration structures initially. This keeps the public API surface small.

## Testing strategy

Use only synthetic PSP-like data already supported by the repository fixtures; no commercial game data is added.

Coverage must prove:

1. A synthetic ISO containing a decrypted ELF boot executable creates a per-module project and an `analyzed` module record.
2. A synthetic ISO containing an encrypted `~PSP` secondary module records `needs_decryption` without aborting the decrypted boot analysis.
3. Multiple decrypted PRX candidates are all processed and supplied to the existing cross-module linker.
4. A malformed secondary module becomes `failed` while another valid module completes.
5. Mirrored project paths cannot escape the game output root.
6. The `game-project` CLI writes the expected reports and summary.
7. Existing `game` scan-only behavior remains unchanged.
8. The complete existing test suite remains green.

## Deferred work

Phase 7B does not add:

- PSP cryptographic decryption;
- recursive scanning of arbitrary resource/archive files;
- game-wide resource conversion;
- cross-module propagated-name injection back into every generated `config/symbols.txt`;
- automatic compiler/version identification;
- ZSO/DAX support;
- parallel module analysis.

Those are separate phases so the whole-game orchestration boundary remains deterministic and testable.
