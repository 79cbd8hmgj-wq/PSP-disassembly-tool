# Phase 8D — Automated Decompile → Build → Match Pipeline

Phase 8D automates the deterministic toolchain Phases 4/5 already proved out (m2c-assisted C drafts, a user-supplied compiler/build system, asm-differ matching) into a queue-driven, resumable, per-function pipeline over an already-analyzed game workspace. It is explicitly **not** an AI/LLM source-rewriting phase: no step in this pipeline generates, edits, or judges C source with a language model. Every stage — decompile, build, match — is the same subprocess-driven, out-of-process tool invocation the toolkit already used in Phases 4 and 5; Phase 8D's job is deciding *what* to run, *when* to stop, and *how to remember* what happened, not writing better code than m2c does.

## Where this fits

```text
analyzed game workspace (Phase 7A-7G / 8A)
        |
        v
discover_functions()  --reads--> game_analysis.json + each project's metadata/functions.json
        |
        v
enrich_with_runtime_evidence() (Phase 8C, optional) / enrich_with_static_confidence() (Phase 6A, optional)
        |
        v
select_functions()  --deterministic queue: smallest-first, needs-work-first, filterable, forceable--
        |
        v
run_function()  per function:
    decompile_project_function() (Phase 4, m2c)
        -> BuildToolchain.compile_function() (external compiler OR the project's own build command)
            -> match_project_function() (Phase 5, asm-differ)
        |
        v
    DecompilationAttempt appended to attempt_history (never overwritten, never deleted)
        |
        v
    select_best_attempt()  --exact > higher similarity > fewer diff rows > deterministic id tiebreak--
        |
        v
save_function_state()  --atomic, workspace/decompilation/functions/<module>/<function>/state.json--
```

## Package layout

```text
src/pspdisasm/decompile/
    workspace.py     # workspace/decompilation/ persistence (own schema version)
    queue.py         # discover_functions, enrich_with_*, QueueFilters, select_functions
    toolchain.py     # BuildToolchain protocol, ExternalCompilerToolchain, ProjectBuildCommandToolchain
    orchestrator.py  # compute_attempt_id, run_function, select_best_attempt, run_and_persist
    reporting.py     # write_match_status_report (workspace/decompilation/reports/match_status.csv)
    __init__.py      # re-exports the public surface (not imported by top-level pspdisasm)
```

`model.py` gained `DecompilationAttempt` and `FunctionDecompilationState` — flat dataclasses (no nested dataclass fields) following the existing convention of storing enum *values* (plain `str`), not enum instances, so `dataclasses.asdict()` round-trips cleanly through JSON. `errors.py` gained `BuildToolchainUnavailableError`, `BuildFailedError`, `UnsupportedFunctionError`, and `ContextGenerationFailedError`, each carrying an optional `.attempt` attribute, matching the `.evidence`/`.provenance` convention already used by Phase 8B/8C errors. Phase 8D reuses the existing two-tier taxonomy unmodified for its own decompile/match steps: `DecompilerUnavailableError`/`DecompilationError` from `decompiler.py`, `MatcherUnavailableError`/`MatchingError` from `matcher.py`.

## Per-function state model

`FunctionDecompilationState` is the persisted, queryable unit: `module`, `function`, `address`, `status` (one of the eight `DecompilationStatus` values — `pending`, `skipped`, `unsupported`, `blocked`, `candidate_generated`, `build_failed`, `matched_partial`, `matched_exact`), `attempts` (count), `best_attempt_id`, `best_match_percent`, optional `static_confidence`/`static_evidence` (Phase 6A), optional `runtime_status` (Phase 8C), `last_failure`, and the full `attempt_history: list[DecompilationAttempt]`.

`DecompilationAttempt` is the append-only provenance record for one generate→build→match cycle: `attempt_id` (content-derived, see below), `variant_reason`, `assembly_sha256`, `context_sha256` (per-context-file hashes), `m2c_command`, `m2c_version`, `target`, `outcome` (a finer-grained `AttemptOutcome`, not the coarse function-level status), plus whatever got as far as running — `candidate_sha256` (decompiled C), `toolchain_name`/`toolchain_identity`, `object_sha256` (built object), `match_raw_score`/`match_max_score`/`match_similarity_percent`/`match_exact`/`matching_rows`/`changed_rows`/`added_rows`/`removed_rows` (asm-differ's own normalized output), `reference_lacks_relocations` (see below), `diagnostics`, and `artifact_paths` (path strings into the project tree, not copies of the artifacts themselves).

`AttemptOutcome` (`decompiled`, `decompilation_failed`, `build_failed`, `match_failed`, `matched_partial`, `matched_exact`) exists specifically so a failure is never collapsed to one bit: the coarse `DecompilationStatus` enum has room for exactly eight function-level states, but a single attempt can fail at three different stages, and losing *which* stage failed would defeat the point of keeping history at all.

## Content-derived attempt identity

`compute_attempt_id()` hashes a canonical JSON payload of `function`, `address`, `assembly_sha256`, `context_sha256`, `m2c_command`, `m2c_version`, `target`, and `toolchain_identity` (sha256, truncated to a 16-hex-character prefix). This is the *entire* cache-invalidation mechanism — there is no separate "invalidate" step, no wall-clock timestamp, no version counter. Change the function's assembly (a Splat re-split, a corrected instruction), change which context files are supplied, change the m2c binary/version, change the target triple, or change the configured compiler/build command/flags, and the next `run_function()` call computes a different id, sees it is not in `attempt_history`, and runs a new attempt — while the old attempt (and its outcome, whatever it was) stays in history untouched. Nothing about the matcher backend (asm-differ path/version, objdump) is part of the id; re-scoring an existing built object with a different asm-differ is out of scope for what "the same attempt" means here — a genuinely different matcher configuration is expected to be exercised through a distinct, filtered run rather than implicitly voiding prior identical attempts.

## Bounded retry, never open-ended

`default_variants(contexts, target)` is the entire variant matrix: the default (no extra context) variant, plus a `with_context` variant when the caller supplied context files — the only two knobs `decompile_project_function()` actually exposes. `run_function(..., max_attempts=2)` slices this list, so supplying more context files never grows the retry count past what's requested. The loop over variants stops early the moment an attempt reaches an exact match, and stops entirely (returning `blocked`) the moment a *global* backend/toolchain is unavailable — `DecompilerUnavailableError` before the loop even starts, or `BuildToolchainUnavailableError`/`MatcherUnavailableError` mid-loop (both signal "this configuration cannot work right now," not "this particular attempt failed"). There is no self-modifying source loop, no LLM judging the generated C, and no unbounded retry: a function that keeps failing simply accumulates a bounded, inspectable history and stops.

## `BuildToolchain`: the missing middle step

Phase 5's `match_project_function()` already accepts a `build_command=` that internally builds-then-matches, but folds a build failure and a match failure into the same `MatchingError` — Phase 8D needs to tell those apart (`build_failed` vs. `match_failed` in the taxonomy), so it performs the build as an independently-typed stage instead:

```python
class BuildToolchain(Protocol):
    name: str
    def identity(self) -> dict[str, object]: ...
    def compile_function(self, source: Path, *, output: Path, project: Path, timeout: float) -> BuildResult: ...
```

- **`ExternalCompilerToolchain(compiler_path, flags=[...])`** — invokes a user-supplied compiler directly (`<compiler> <flags> -c <source> -o <output>`). There is no universal PSP compiler, so unlike most backends in this codebase there is no PATH-searched default name; the caller must pass an explicit path or set `PSPDISASM_BUILD_COMPILER`.
- **`ProjectBuildCommandToolchain(command_template, output_template)`** — runs the project's own build system (e.g. a Splat-generated Makefile rule) for one function. Both templates take a `{function}` placeholder (the candidate C file's stem); the command is parsed with `shlex.split` and executed as an argument array, never `shell=True` — a shell-metacharacter-laden function name is passed through as a single literal argument, not interpreted (`test_project_build_command_toolchain_never_uses_shell_features`). The toolchain's own resolved `output_template` path is authoritative; the caller's requested `output` is a hint only, since a build system chooses its own output location.

`orchestrator.run_function()` then calls `match_project_function(..., candidate_object=<already-built-object>, build_command=None)`, so Phase 5's own build-then-match path is simply unused by Phase 8D — matching still goes through the exact same, already-tested function.

## Best-attempt selection

`select_best_attempt(attempts)` ranks by `(0 if exact else 1, -similarity_percent, changed+added+removed rows, attempt_id)` and takes the minimum — exact beats any partial match, higher similarity beats lower, fewer structural diff rows beat more at equal similarity, and a fully deterministic string comparison breaks any remaining tie. Attempts are **never deleted or overwritten**: `run_function()`'s final `FunctionDecompilationState.status` is derived from whichever attempt currently ranks best across the *entire* accumulated history, so a later, worse-scoring attempt (e.g. one probing a `with_context` variant that turns out to hurt the match) can never regress an already-achieved exact match — `test_worse_attempt_never_replaces_better_attempt` constructs exactly this case.

## The reference-object relocation weakness

Phase 5's `build_reference_object()` synthesizes a single-function ELF containing the *original instruction words* but **no MIPS relocation records** — `matcher.py::_reference_warning()` already detects this (checking `metadata/references.json` for a `source_function` match) and emits a pessimism warning. Phase 8D does not attempt to fabricate correct relocations for that synthetic object; doing so risks silently inventing incorrect target addresses for calls/global references, which would be worse than an honestly pessimistic score. Instead, `run_function()` replicates the same references.json check as `_function_has_known_references()` and threads the result through as `DecompilationAttempt.reference_lacks_relocations: bool` — a structured, machine-readable flag callers can use to discount a low similarity score for exactly the functions where the reference object is known to be missing evidence, rather than either fabricating relocations or leaving the caller to re-derive the warning from free text. Full relocation-embedding in `build_reference_object()` remains explicitly deferred to a separate later task.

## Workspace schema

```text
workspace/
  decompilation/
    schema_version.json                          # independent of ANALYSIS_SCHEMA_VERSION and RUNTIME_SCHEMA_VERSION
    functions/<module-path-segments>/<function>/state.json
    reports/match_status.csv
```

All writes are atomic (write to a `.tmp` sibling, then `replace()`), matching `workspace.py`/`runtime/workspace.py`. `DECOMPILATION_SCHEMA_VERSION` is checked on both read and write, independent of the other two schema versions: running the decompile pipeline never forces a static re-analysis or discards runtime evidence, and vice versa. Module/function path segments are validated against traversal and symlink escape (`_function_dir`, mirroring `game_project.py::_safe_relative_target`) before touching the filesystem. Generated candidate C/object files themselves stay in the existing project tree (`src/nonmatching/<function>.<attempt_id>.c`, `build/nonmatching/<function>.<attempt_id>.o`) exactly where `decompile_project_function()`/a `BuildToolchain` already write them — only hashes and path strings are persisted under `workspace/decompilation/`, so a function retried many times does not duplicate large artifacts into workspace state.

## Queue: deterministic, non-ML prioritization

`discover_functions(workspace_dir)` enumerates every function in every `analyzed`/`analyzed_recovered` module's Splat project (reading only what Phase 7/8A already produced — `game_analysis.json`, each project's `metadata/functions.json` — computing nothing new), attaching existing persisted state or a fresh `pending` state. `enrich_with_runtime_evidence()` (optional) attaches the worst/most-important Phase 8C reconciliation status covering a function's address range — a `conflicting` runtime observation is surfaced, never silently promoted to a hard fact. `enrich_with_static_confidence()` (optional, opt-in because it costs a disassembly pass per module) attaches Phase 6A `analyze_advanced()` function-confidence scores for future tie-breaking; it degrades gracefully (no confidence data, not a crash) when the optional analysis engines aren't installed.

`select_functions(functions, QueueFilters(...))` is the actual prioritization: `--function` (name or `0x`/decimal address) bypasses ordering and the default "skip already-done" filter entirely — this is both direct dispatch and the "force a retry on one already-matched function" mechanism. Otherwise, `matched_exact`/`skipped`/`blocked`/`unsupported` functions are excluded by default (`--unmatched-only` narrows further to exactly `matched_exact`; `--below-match PERCENT` selects only functions whose best match is below a threshold, regardless of exact status), and everything else sorts smallest-function-first with a fully deterministic `(size, module, function, address)` tiebreak — repeated calls over unchanged input always produce the same order, so partial pipeline runs (`--limit N`) always pick up the next functions rather than reshuffling.

## CLI

```bash
pspdisasm decompile-workspace WORKSPACE \
  --m2c /path/to/m2c.py \
  --compiler /path/to/psp-gcc --compiler-flag -O2 \
  --asm-differ /path/to/diff.py --objdump /path/to/psp-objdump

pspdisasm decompile-workspace WORKSPACE \
  --m2c /path/to/m2c.py \
  --toolchain-command "make {function}.o" --toolchain-output "build/{function}.o" \
  --asm-differ /path/to/diff.py --objdump /path/to/psp-objdump \
  --module PSP_GAME/SYSDIR/EBOOT.BIN --below-match 90 --limit 20

pspdisasm decompile-workspace WORKSPACE --function func_08812340 --force  # force-retry one function

pspdisasm match-status WORKSPACE
pspdisasm match-status WORKSPACE --json -
```

`--compiler`/`--compiler-flag` (repeatable) select an `ExternalCompilerToolchain`; `--toolchain-command`/`--toolchain-output` (both required together, mutually exclusive with `--compiler`) select a `ProjectBuildCommandToolchain`. `--module`, `--function`, `--below-match`, `--unmatched-only`, and `--limit` mirror `QueueFilters` exactly. `--static-confidence` opts into the Phase 6A enrichment pass. Every `decompile-workspace` run persists each processed function's state immediately (`run_and_persist`) and regenerates `workspace/decompilation/reports/match_status.csv` at the end; `match-status` reads persisted state only (it decompiles/builds/matches nothing) and regenerates the same report, so it is safe to run at any time as a read-only progress check.

## Tests

55 tests across `test_decompile_workspace_state.py` (12: persistence round-trip, schema versioning, path-traversal/symlink rejection, atomic writes, cross-marker isolation from `analysis/`/`runtime/`), `test_decompile_workspace_toolchain.py` (13: both toolchains' success/failure/timeout/identity paths, and the never-uses-a-shell proof), `test_decompile_workspace_queue.py` (17: discovery, enrichment, every filter, deterministic ordering, forced-retry bypass), and `test_decompile_workspace_orchestrator.py` (13: full pipeline to an exact match, isolated build failure, partial match, best-attempt ranking, resume/dedup, content-change invalidation, unsupported functions, both `blocked` paths, bounded retries, never-regress selection, and `run_and_persist`), plus 6 more in `test_cli_decompile_workspace.py` covering both toolchain CLI paths, argument validation, JSON output, and `match-status`. Full suite: 422 passed, 1 skipped (unchanged, pre-existing m2c-unavailable skip) — every pre-Phase-8D test continues passing unmodified. Repository payload guard passes.

## Deferred (explicitly out of scope this phase)

- Full relocation-embedding in `build_reference_object()` (see above) — `reference_lacks_relocations` is the honest, structured flag instead.
- "First differing location" or any other asm-differ output normalization beyond the row classification (`matching`/`changed`/`added`/`removed`) Phase 5 already produces.
- Call-graph/complexity-based queue weighting beyond the optional Phase 6A static-confidence attachment (which is not yet consumed as a sort key, only attached to state for a caller/future phase to use).
- A separate `retry-function` CLI command — `decompile-workspace --function SELECTOR --force` already covers forced re-runs.
- Any compiler auto-discovery framework — `ExternalCompilerToolchain`/`ProjectBuildCommandToolchain` require an explicit path/template, matching how `--m2c`/`--asm-differ`/`--objdump` already work.
- Any AI/LLM-driven source rewriting, self-modifying source loop, or automated code-quality judgment of the generated C — Phase 8D orchestrates the existing deterministic toolchain only.
- Phase 8E (Ghidra integration) and any GUI work — none of this was touched.
