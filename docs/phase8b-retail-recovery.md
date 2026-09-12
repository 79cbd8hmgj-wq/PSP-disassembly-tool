# Phase 8B — Retail Executable Recovery

Phase 8B adds a pluggable recovery layer that lets an encrypted `~PSP` container turn into a directly analyzable PSP ELF/PRX before it re-enters the existing Phase 1–7G analysis pipeline. It does not implement PSP decryption. It defines the boundary a user-supplied recovery tool or pre-verified dump must satisfy, verifies whatever comes back, and records deterministic hash provenance for it.

## Where this fits

```text
retail ~PSP bytes
        |
        v
detect.py / psp_container.py        (unchanged: parses the header, flags needs_decryption)
        |
        v
recovery.py: RecoveryBackend orchestration
        |
        +--> ExternalDecryptorBackend   (subprocess: --input IN --output OUT)
        +--> PrebuiltDumpBackend        (verified pre-decrypted dump manifest)
        +--> a future/user backend      (same RecoveryBackend protocol)
        |
        v
strict verification gate (recovery.py::recover_bytes)
        |
        v
verified PSP ELF/PRX  -->  the existing analyze/disassemble/link/place/project pipeline, unmodified
```

The MIT core (`recovery.py` and everything upstream of it) contains no PSP cryptography. Every backend that can actually decrypt something lives entirely out-of-process (a subprocess) or is reduced to a hash-verified handoff of bytes the user already produced (`PrebuiltDumpBackend`). See [Licensing boundary](#licensing-boundary).

## Backward compatibility

`generate_game_project()` and `analyze_game_workspace()` both accept `recovery_backends: Iterable[RecoveryBackend] = ()`. With no backend configured (the default), an encrypted module is recorded exactly as it was before Phase 8B: `status="needs_decryption"`, `recovery=None`, counted only in `needs_decryption_count`. No existing consumer — including `fight_night`'s toolkit adapter, which is pinned to an exact `pspdisasm` revision and only ever inspects `needs_decryption` — needs to know Phase 8B exists.

## Data model

- `RecoveryBackend` (Protocol, `recovery.py`) — `name: str`, `probe(header: PspContainerHeader, data: bytes) -> float`, `recover(data: bytes) -> RecoveredPayload`. Mirrors the existing `ResourceContainerParser` protocol's probe/select shape.
- `RecoveredPayload` — `data: bytes`, `backend_version: str | None`, `diagnostics: list[str]`. What a backend hands back before verification.
- `RecoveryProvenance` (`model.py`, since `ExecutableModel.recovery` needs it) — `outcome`, `original_sha256`, `recovered_sha256`, `recovery_backend`, `backend_version`, `verification`, `warnings`. Attached to `ExecutableModel.recovery` on success, and to `GameModuleAnalysisRecord.recovery` on every attempt, success or failure.
- `RecoveryResult` — `model: ExecutableModel`, `data: bytes`, `provenance: RecoveryProvenance`. Returned by `recover_bytes()` only on success.
- `RecoveryOutcome` (`str, Enum`, `recovery.py`) — the closed set of machine-readable outcomes: `no_backend_accepted`, `backend_unavailable`, `backend_failed`, `output_too_large`, `output_unchanged`, `output_invalid`, `output_still_encrypted`, `verified`. "No backend configured at all" is represented by `recovery is None` rather than a ninth enum member, since it is a property of the caller's configuration, not of an attempt.

## Verification contract

Phase 8B recovery is successful **only** when all of the following hold:

1. the input was a `~PSP` container that reported `needs_decryption`;
2. the backend's output differs from the input bytes;
3. the output is within the configured size bound (default 64 MiB — no genuine PSP ELF/PRX exceeds total PSP RAM);
4. the output is recognized and parsed as a valid ELF32 PSP executable (`InputKind.ELF32`, not `InputKind.PSP_CONTAINER`);
5. the resulting `ExecutableModel.needs_decryption` is `False`.

Anything else — including a backend that returns another `~PSP` container — is a verification **failure**, not a partial success and not a signal to retry. Phase 8B recursion is exactly one hop: `recover_bytes()` calls `detect_input()` once on the backend's output and, if that is still `PSP_CONTAINER`, raises `RecoveryVerificationError` with `outcome="output_still_encrypted"`. It never calls a recovery backend a second time on that output. Multi-stage recovery (e.g. compression-then-encryption) is left for a future phase if real-game evidence shows it is needed.

## Failure taxonomy

| Exception | `RecoveryOutcome` | Meaning |
|---|---|---|
| `RecoveryBackendUnavailableError` | `no_backend_accepted` | No configured backend probed above threshold for this container (including an empty backend list). |
| `RecoveryBackendUnavailableError` | `backend_unavailable` | A selected backend could not run at all (executable missing, `OSError` on exec). |
| `RecoveryError` | `backend_failed` | The backend ran but failed (nonzero exit, exception, missing output file). |
| `RecoveryOutputTooLargeError(RecoveryError)` | `output_too_large` | Output exceeded the configured byte bound. |
| `RecoveryVerificationError(RecoveryError)` | `output_unchanged` | Output hash equals input hash. |
| `RecoveryVerificationError(RecoveryError)` | `output_invalid` | Output does not parse as a recognizable, directly analyzable ELF32 PSP executable. |
| `RecoveryVerificationError(RecoveryError)` | `output_still_encrypted` | Output is itself a `~PSP` container. |
| *(none — `RecoveryResult` returned)* | `verified` | All five verification conditions above are satisfied. |

Every raised exception carries a `.provenance: RecoveryProvenance` attribute with the outcome and whatever hashes/backend identity were known at the point of failure, so callers never have to parse a warning string to distinguish these cases.

## Game-wide integration

In `game_project.py`'s existing first analysis pass, the point that previously unconditionally recorded `status="needs_decryption"` now branches:

- **no backend configured** (`recovery_backends=()`, the default): behavior is byte-for-byte identical to pre-Phase-8B.
- **backend(s) configured, recovery fails**: the module is still recorded as `status="needs_decryption"` (never `"failed"` — a missing/failed recovery is an expected, ordinary outcome, not a toolkit integrity error), with a warning and the failure's `RecoveryProvenance` attached. This failure is isolated exactly like any other secondary-module failure: the rest of the game (other modules, resources, links) is still analyzed.
- **backend(s) configured, recovery succeeds**: the recovered bytes are written atomically to `<output>/recovered/<module path>` alongside an atomically-written `<module path>.recovery.json` provenance sidecar, and that recovered file — not the original encrypted one — flows through the same placement/disassembly/Splat/linking code every native ELF/PRX goes through. The module is recorded as `status="analyzed_recovered"`, distinct from `status="analyzed"` for a module that was already a native ELF/PRX.

`GameProjectResult.recovered_count` is a new, deterministic field counting `analyzed_recovered` modules; it is disjoint from `analyzed_count`, so "how many modules were natively analyzable" and "how many needed recovery" both stay independently answerable. `analyzed_count + recovered_count` is the total successfully analyzed.

## Workspace cache identity

`workspace.py::analyze_game_workspace()`'s resumable-analysis cache key (`_analysis_key`) folds in each configured backend's `.name` and the configured `recovery_max_output_bytes`. Both concrete backends derive `.name` from their own configuration content (`ExternalDecryptorBackend` embeds its resolved command; `PrebuiltDumpBackend` embeds a hash of its manifest file), so changing which backend is configured — or editing a prebuilt-dump manifest in place — invalidates the cache and forces a fresh analysis, while an unchanged configuration reuses cached results exactly as before. `ANALYSIS_SCHEMA_VERSION` was bumped from 1 to 2 for this phase, so any pre-Phase-8B cached `analysis/state.json` (which lacks `recovered_count`) is treated as stale and re-analyzed once, rather than read with a missing field.

## CLI

```bash
pspdisasm recover LOCKED.PRX recovered.elf --recovery-backend /path/to/psp-recover-tool
pspdisasm recover LOCKED.PRX recovered.elf --recovery-manifest dumps.json
pspdisasm game-project game.iso game_decomp --recovery-backend /path/to/psp-recover-tool
pspdisasm analyze-workspace workspace --recovery-manifest dumps.json
```

`--recovery-backend PATH` and `--recovery-manifest FILE` may each be repeated; `--recovery-max-bytes N` overrides the default 64 MiB bound. `recover` is a single-file entry point independent of the whole-game pipeline, useful for testing a backend or manifest in isolation.

## `ExternalDecryptorBackend` contract

The tool is invoked as `<command> --input IN --output OUT` with an argument list (never `shell=True`), inside a per-call temporary directory. It must read arbitrary `~PSP` bytes from `IN` and, on success, write a decrypted PSP ELF/PRX to `OUT` and exit `0`. `stdout`/`stderr` are captured and bounded to 2000 characters in any resulting error message. The output file's size is checked with `stat()` and rejected if it exceeds the bound *before* it is read into memory — an oversized or unbounded output can never be fully buffered. Backend version detection is best-effort (only for a `.py` script with an adjacent `pyproject.toml`); a tool with no discoverable version still succeeds with `backend_version=None`, by design — there is no `--version` convention recovery depends on.

Because the tool runs entirely out-of-process and the toolkit never imports, links, or bundles it, it may be GPL-licensed or wrap PPSSPP/KIRK-compatible tooling the user is independently licensed to run.

## `PrebuiltDumpBackend` contract

The manifest is a JSON list of objects:

```json
[
  {
    "original_sha256": "<sha256 of the encrypted ~PSP bytes>",
    "recovered_sha256": "<sha256 of the already-decrypted file>",
    "path": "relative/path/to/recovered.elf"
  }
]
```

`path` is resolved relative to the manifest's own directory. Both traversal (`..`, absolute paths) and any symlink along the literal resolved path are rejected at manifest-load time, matching the existing `workspace.py` "no symlinks in extracted PSP sources" policy rather than only checking containment after resolution. Recovery for one input binds all three pieces: the input's own SHA-256 must match a manifest entry's `original_sha256`, the referenced file must exist, and its actual SHA-256 must match that entry's `recovered_sha256` — a manifest is never trusted on the `original_sha256 -> path` mapping alone. The recovered bytes still pass through the exact same verification gate (`recover_bytes()`) as any other backend's output.

## Licensing boundary

No PPSSPP GPL source, no KIRK implementation, and no PSP key material of any kind is present in this repository. `recovery.py` defines a protocol and a verification gate; the two concrete backends either shell out to a tool the user supplies and is responsible for licensing appropriately, or verify a dump the user already produced by some other means. This mirrors the existing precedent for `decompile`/`match`, where `m2c` (GPLv3) and `asm-differ` are likewise invoked out-of-process and never vendored.

A separate, unrelated project (`fight_night`) has its own from-scratch PPSSPP WebSocket debugger client used for runtime capture experiments. That code is relevant to a future Phase 8C (general PSP runtime intelligence) and is explicitly out of scope here — Phase 8B does not port, reuse, or depend on it.

## Tests

`tests/test_recovery.py` covers backend selection (deterministic tie-breaking, probe-exception isolation, invalid-confidence rejection), every `recover_bytes()` failure outcome, `ExternalDecryptorBackend` (subprocess success/nonzero-exit/missing-output/oversized-output-without-a-full-read/bounded-diagnostics), and `PrebuiltDumpBackend` (hash binding both directions, path traversal, absolute paths, symlink escape). `tests/test_game_project.py` covers game-wide integration: no-backend-configured behavior is asserted identical to pre-Phase-8B, a configured backend recovers a module and it falls through the normal disassembly/Splat/linking pipeline, and a failing backend is isolated to its own module without aborting the rest of the game. `tests/test_workspace.py` covers cache reuse/invalidation on backend identity and output-bound changes. `tests/test_cli_recovery.py` covers the `recover` subcommand and the `--recovery-backend`/`--recovery-manifest` flags on `game-project`. All fixtures are synthetic (`tests/fixtures.py`'s existing `build_psp_container_header()`/`build_allegrex_elf32()` plus a `FakeRecoveryBackend` test double); no retail PSP data, real encrypted modules, decrypted commercial modules, keys, or key tables are present anywhere in the test suite.

## Limitations

- Single-stage recovery only; a backend producing a still-encrypted or still-compressed intermediate result is a verification failure, not progress.
- `ExternalDecryptorBackend.probe()` always returns `1.0` — an explicitly configured external backend is assumed to accept whatever container it is given; per-compression-mode probing is left to a future backend if that distinction becomes useful.
- No bundled recovery backend of any kind ships with this toolkit, by design.
