# Phase 8C — General PSP Runtime Intelligence

Phase 8C turns PPSSPP from a static-analysis behavioral reference (Phase 7A–7G, 8B) into an optional, driven, out-of-process evidence source: capture what actually happens at runtime, map it back to the correct static PSP module/function via an already-analyzed workspace, and persist categorical, machine-readable evidence that corroborates or conflicts with static conclusions. It does not implement PSP crypto, does not bundle or link against PPSSPP, and does not replace or overwrite any static analysis.

## Where this fits

```text
analyzed PSP workspace (Phase 7A-7G / 8A)
        |
        v
RuntimeSession (connect to, or launch, a user-supplied PPSSPP)
        |
        v
PpssppDebuggerTransport (PPSSPP's own WebSocket JSON debugger protocol)
        |
        v
RuntimeBreakpointObservation  --(atomic, workspace/runtime/)-->  persisted evidence
        |
        v
RuntimeModuleMap (tiered, never fabricated)
        |
        v
reconcile_workspace()  --uses--> this workspace's own module_placements.json
        |
        v
RuntimeReconciliation: unresolved | inferred | corroborated | runtime_observed | runtime_verified | conflicting
```

## Provenance: what's generalized from Fight Night, what's new

`fight_night`'s `src/fnr3_re/ppsspp_debugger.py`, `ppsspp_bundle.py`, `save_runtime_9e_capture.py`, and `save_runtime_9e_evidence.py` already proved the underlying mechanics work: WebSocket handshake/framing, JSON debugger request/response correlation, register reads, memory reads, breakpoint add/remove, resume, backtrace, bundle verification, controlled subprocess launch, and bounded runtime capture. That project is game-specific (Fight Night Round 3, revision-pinned) and Task-9E-specific (one save-corruption A/B comparison experiment), and its repository carries no license. Phase 8C is a from-scratch, MIT-owned reimplementation of the *general* mechanics it proved out — no file was copied — with the game-specific and Task-9E-specific pieces (plan/checkpoint schemas, save-mutation comparison, ULUS10066 assumptions, pinned bundle hashes) deliberately left behind. See [Licensing](#licensing).

## Package layout

```text
src/pspdisasm/runtime/
    transport.py       # PpssppDebuggerTransport
    bundle.py           # verify_ppsspp_bundle (generalized, no pinned profile)
    session.py         # RuntimeSession, LaunchSpec
    modules.py          # RuntimeModuleSource tiers, build_runtime_module_map
    reconciliation.py  # StaticCandidate, ObservationGroup, reconcile_*
    workspace.py        # workspace/runtime/ persistence
    __init__.py         # re-exports the public surface (not imported by top-level pspdisasm)
```

`model.py` gained `RuntimeAddress`, `RuntimeAddressDomain`, `RuntimeSessionInfo`, `RuntimeRegisterSnapshot`, `RuntimeMemoryObservation`, `RuntimeBacktrace`, `RuntimeBreakpointObservation`, `RuntimeModule`, `RuntimeEvidenceSet`, `RuntimeReconciliation` — plain dataclasses following the existing convention of storing enum *values* (plain `str`), not enum instances, so `dataclasses.asdict()` round-trips cleanly through JSON exactly like every other model in this codebase. `errors.py` gained `RuntimeBackendUnavailableError`, `RuntimeConnectionError`, `RuntimeProtocolError`, `RuntimeTimeoutError`, `RuntimeCaptureError`, `RuntimeMappingError`, each carrying an optional `.evidence` attribute.

## Runtime address model

Four address domains (`RuntimeAddressDomain`) are never collapsed into a bare `int`:

- `runtime` — observed live in the PPSSPP process (a breakpoint hit address, a module's observed base).
- `analysis` — the address space `FunctionRecord`/`SymbolRecord`/`CallGraphEdge`/`JumpTableRecord` and `ModulePlacement.load_address` already use (i.e. what `disassemble_file(..., load_address=placement.load_address)` produced).
- `elf_virtual` — the original file's pre-placement ELF vaddr (reserved for future use; reconciliation does not currently need it since analysis-domain addresses are what static records already carry).
- `module_relative` — an offset from one `RuntimeModule`'s *observed* runtime base.

Every `RuntimeAddress` also carries an optional `module_path` once it's been attributed to a module. The reconciliation path is exactly: runtime address → runtime module range → module-relative offset → that module's own static `load_address` → analysis address → match against static candidates. The offset is computed from the **observed** runtime base, never from an assumed one — `tests/test_runtime_reconciliation.py::test_reconcile_observation_uses_real_runtime_base_even_when_it_differs_from_analysis_placement` constructs a case where the synthetic Phase 7G analysis placement and the real observed runtime base are deliberately different addresses, and reconciliation still lands on the correct static function because only the *offset* ever crosses between the two address spaces.

## Transport: `PpssppDebuggerTransport`

An independent client for PPSSPP's documented WebSocket JSON debugger protocol (HTTP upgrade handshake, RFC6455 framing, `{"event", "ticket", ...}` request/response correlation, unsolicited events queued by name). Proven request vocabulary carried over from the project-owned reference client: `version`/`client.config.set` (sent on connect), `cpu.getAllRegs`, `memory.read`, `cpu.breakpoint.add`/`remove`, `cpu.resume`, `hle.backtrace`. Explicit bounds not present in that single-purpose client:

- separate `connect_timeout` and `request_timeout`;
- `max_frame_bytes`, checked against the frame's declared length *before* the mask key or payload is read — an oversized frame is rejected without ever attempting to buffer it;
- `max_queued_events` bounds the per-event-name deque so an unbounded unsolicited-event stream can't grow memory without limit;
- every I/O failure raises a typed error (`RuntimeConnectionError`/`RuntimeProtocolError`/`RuntimeTimeoutError`) instead of a raw `socket`/`json` exception;
- `try_request()` is a capability probe: an `error` debugger response or a timeout both return `None` rather than raising, which is what lets module-mapping tier 1 fail through cleanly instead of crashing when an event isn't supported.

## Session: `RuntimeSession`

A higher-level context manager over one transport connection. Two modes:

- **connect** (default): attach to an already-running, user-supplied PPSSPP.
- **launch** (`launch=LaunchSpec(executable=..., args=..., cwd=...)`): start a user-supplied executable via `subprocess.Popen` with an argument list (never `shell=True`), retry-connecting until the debugger port is reachable or the process exits (whichever comes first — a process that exits early raises `RuntimeBackendUnavailableError` immediately rather than retrying for the full timeout).

`close()` — called automatically on `__exit__`, including when an exception propagates out of the `with` block — always removes every breakpoint this session installed (tracked internally, best-effort on each removal) before closing the transport, and in launch mode always terminates (then kills, if needed) the process it started. A connect-mode session never touches a process it did not launch, so it can never orphan or kill something the user is running interactively.

`observe_breakpoint(address, timeout, memory_reads=(), capture_registers=True, capture_backtrace=True, max_backtrace_depth=32, max_total_memory_bytes=64*1024)`:

```text
install breakpoint -> resume -> wait (bounded, explicit timeout)
  -> capture registers (bounded to one request)
  -> capture bounded memory reads (bounded per-read AND in total, checked before any read is issued)
  -> capture bounded backtrace (depth-limited)
  -> finally: always remove the breakpoint, and defensively resume once more
     (never leave a real PPSSPP window paused because *this* capture failed)
```

A timeout waiting for the hit, a capture failure after the hit, or a bound violation before installing anything all raise `RuntimeCaptureError` — the breakpoint is removed in every one of those paths (`tests/test_runtime_session.py` exercises the success path, the wait-timeout path, and the pre-install bound-rejection path explicitly).

## Module mapping: tiered, never fabricated

`RuntimeModuleSource` is a `probe`-free Protocol: just `name` and `discover(transport) -> list[RuntimeModule]`. `build_runtime_module_map(transport, sources)` tries sources **in the given order and returns the first non-empty result** — tiers are never merged, so a mapping never blurs "PPSSPP told us this" with "the user guessed this."

- **`HleModuleListSource`** (tier 1): probes an HLE module-list event (`try_request`, default name `hle.module.list`) and parses whatever comes back defensively. **This event's existence and schema are not verified against real PPSSPP** by anything in this repository — the reference material this phase generalized from never exercised it. An unsupported/error/timeout response returns `[]`, falling through to the next tier. Resolving this uncertainty is exactly what the live test (see below) is for.
- **Kernel-structure-based mapping** (tier 2/3 in the design): **not implemented**. Reserved as a `RuntimeModuleSource` extension point; walking PSP loader/HLE structures directly out of PPSSPP's memory needs its own evidence-gathering pass this phase did not do.
- **`UserProvidedModuleSource`** (the Phase 8C baseline): an explicit `{module_path: runtime_base}` mapping (CLI `--module-base PATH=0xADDRESS`, repeatable). Every produced `RuntimeModule.evidence` says plainly "not toolkit-proven." When this workspace's own `module_placements.json` has an entry for that path, the module is sized from that real static fact (`image_size`) rather than left unsized — `load_static_placements(workspace_dir)` reads it, returning `{}` (not an error) when static analysis hasn't produced one yet.

## Reconciliation

`reconcile_observation(observation, *, modules, module_placements, static_candidates)` is a pure function: no I/O, fully unit-testable with synthetic data. It returns a `RuntimeReconciliation` and never raises for an unprovable mapping — it downgrades to `unresolved`/`runtime_observed` instead:

1. Find the `RuntimeModule` whose runtime range contains the observation's address (a module with an unknown size matches at-or-after its base, the best that can be said without a bound; a module with a known size takes priority when both could match). No match → `unresolved`.
2. `offset = runtime_address - module.runtime_base`. If the module has no `static_module_path` → `runtime_observed` (we know the offset, not which static module it's in).
3. Look up that path's `module_placements[path]["load_address"]`. Missing → `runtime_observed`.
4. If the static placement also declares `image_size` and `offset` exceeds it, that's a genuine discrepancy (the real runtime module is bigger than static analysis captured) → `conflicting`, not silently ignored.
5. `analysis_address = load_address + offset`. Match against `static_candidates[path]` at that exact address. No match → `runtime_observed` (the analysis address is still recorded — useful even without a static hit). A match → `corroborated`.

`reconcile_workspace(groups, ...)` is the batch/stateful layer: each `ObservationGroup` binds one observation to a caller-chosen `call_site_key`. Repeated observations resolving to the same `(call_site_key, target)` pair accumulate `observation_count` and escalate `corroborated` → `runtime_verified` on the second and later hit — this is the literal `sub_089A7420` / `offset 0x17420` / "observed 27 times" example from the roadmap, reproduced as `test_reconcile_workspace_escalates_to_runtime_verified_on_repeat_observations`. Two observations sharing a `call_site_key` but resolving to *different* targets are both kept, both re-flagged `conflicting`, and neither is erased (`test_reconcile_workspace_flags_conflicting_targets_at_same_call_site_without_erasing_either`). One malformed/unresolvable observation in a batch never prevents the rest from reconciling.

Evidence states are the closed set `unresolved | inferred | corroborated | runtime_observed | runtime_verified | conflicting` — no additive/hidden confidence scoring. `inferred` is reserved for a purely static claim that reconciliation hasn't touched yet (no runtime evidence exists for it); Phase 8C's reconciliation functions themselves only ever produce the other five.

## Workspace schema

```text
workspace/
  runtime/
    schema_version.json          # independent of ANALYSIS_SCHEMA_VERSION
    sessions/<session_id>.json   # RuntimeSessionInfo
    evidence/<session_id>/observations.json
    modules.json                 # latest RuntimeModuleMap
    reconciliation.json          # latest RuntimeReconciliation list
```

All writes are atomic (write to a `.tmp` sibling, then `replace()`), matching the convention already established in `workspace.py`/`game_project.py`. `RUNTIME_SCHEMA_VERSION` is checked on both read and write and is completely independent of `ANALYSIS_SCHEMA_VERSION`: capturing new runtime evidence never invalidates the static-analysis resumable-analysis cache, and re-running static analysis never touches `workspace/runtime/`. Session ids are validated against path traversal (`_safe_session_id`) before touching the filesystem. No raw memory bytes are ever persisted — `RuntimeMemoryObservation` stores only `size` and `sha256`, matching what the project-owned reference implementation already did for the same reason.

## CLI

```bash
pspdisasm runtime observe WORKSPACE --port PORT --address ADDRESS --timeout SECONDS
pspdisasm runtime observe WORKSPACE --port PORT --launch PPSSPP_EXECUTABLE --address ADDRESS
pspdisasm runtime modules WORKSPACE --port PORT [--module-base PATH=0xADDRESS ...]
pspdisasm runtime reconcile WORKSPACE [--static-candidates FILE]
```

`--host`/`--port`/`--launch`/`--launch-arg`/`--connect-retry-seconds`/`--session-id` are shared connection flags. `observe` persists the observation (appending to that session's `observations.json`) and the session's own info; `modules` persists the module map; `reconcile` reads every persisted session's observations plus the module map plus this workspace's own `module_placements.json`, and writes `reconciliation.json`. `--static-candidates FILE` is a JSON object mapping module path → list of `{"kind", "address", "evidence"}` — deriving these automatically from disassembly output is explicitly deferred (see Limitations). No full debugger shell/REPL is provided, by design.

## Fake-debugger test design

`tests/fake_ppsspp_server.py` is a real `socket`-based TCP server performing the actual WebSocket handshake and the same JSON vocabulary, scriptable per test: a handler function reads/writes frames directly, so a test can send malformed JSON, an unmasked/fragmented frame, an oversized declared frame length, close mid-request, or simply never respond. `tests/test_runtime_transport.py` (18 tests) covers handshake success/failure, deterministic sequential ticket assignment, response correlation around unsolicited events, malformed JSON, fragmented frames, oversized frames (proving the payload is never read), request timeout, disconnect, event queuing/delivery, and the register/memory/breakpoint/backtrace/capability-probe wrappers. `tests/test_runtime_session.py` (8 tests) covers connect mode, launch mode (a real subprocess running a small script that imports the same fake server fixture), breakpoint removal after both success and timeout, memory-bound rejection before any breakpoint is installed, cleanup after an exception inside a `with` block, and — directly — that a launched process is verified terminated (`process.poll() is not None`) after `close()`.

## Live-test boundary

No live PPSSPP test is included in this phase (none was required to reach the stated acceptance milestone with synthetic data, and adding one without a real bundle to validate against would just be more untested code). A future live test should follow the existing environment-gated pattern (skip unless e.g. `PSPDISASM_LIVE_PPSSPP_BUNDLE`/`_ISO` are set) and — critically — is what actually resolves the `HleModuleListSource` uncertainty above; it must contain no Fight-Night-specific addresses, revisions, or Task 9E concepts.

## Licensing

No PPSSPP source, no KIRK implementation, no PSP key material. `pspdisasm.runtime.transport` is an independent client for PPSSPP's own documented protocol, generalized (not copied) from a project-owned, unlicensed reference implementation in a separate repository; this phase treats the result as MIT-owned toolkit code from first commit, per that repository's owner's own direction. PPSSPP itself is driven entirely as a user-supplied, out-of-process program — connected to via loopback WebSocket or launched as a subprocess — exactly as m2c/asm-differ/Phase 8B recovery backends already are.

## Tests

75 new tests across `test_runtime_transport.py` (18), `test_runtime_bundle.py` (8), `test_runtime_session.py` (8), `test_runtime_modules.py` (9), `test_runtime_reconciliation.py` (12), `test_runtime_workspace.py` (15), and `test_cli_runtime.py` (5). Full suite: 358 passed, 1 skipped (unchanged, pre-existing m2c-unavailable skip) — all 283 pre-Phase-8C tests continue passing unmodified. Repository payload guard passes; no emulator binary, game payload, save state, or PPSSPP bundle is present anywhere in the repository or test suite.

## Deferred (explicitly out of scope this phase)

- Kernel-structure-based module mapping (tier 2/3).
- Automatic derivation of `static_candidates` from `game_analysis.json`/disassembly output (currently caller-supplied).
- Multi-session/multi-build evidence fusion beyond per-`(call_site, target)` observation counts.
- A live PPSSPP test.
- Phase 8D (decompile/build/match automation), Phase 8E (Ghidra integration), GUI work, and any Fight-Night-specific logic — none of this was touched.
