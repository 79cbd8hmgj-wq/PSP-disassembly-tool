# Phase 8B — Real-Game Compatibility

## Purpose

Phase 8A proved that the toolkit can ingest and resumably analyze a full retail-size PSP game locally, but the first real acceptance run exposed coverage gaps that the earlier synthetic/fixture-driven phases did not make obvious.

For *Need for Speed: Most Wanted 5-1-0 (USA)*, the first workspace run reported:

- 25 executable candidates
- 10 analyzed
- 9 `needs_decryption`
- 6 `failed`
- 840 resources
- 40 recognized resources
- 800 unknown resources

Phase 8B turns those outcomes into actionable compatibility work. The goal is not to special-case one title. NFS Most Wanted is the first acceptance-test game used to force generic PSP compatibility improvements.

## Success definition

The toolkit should move from "the pipeline ran" to "every candidate has a useful, evidence-backed result."

For executable candidates, every candidate must end in one of these states:

1. `analyzed` — usable executable successfully analyzed;
2. `recovered_and_analyzed` — encrypted/compressed PSP container recovered through an approved recovery backend and then analyzed by the normal pipeline;
3. `unsupported_recovery` — container was identified precisely, but no safe supported recovery backend is available;
4. `invalid_candidate` — evidence shows the item was not a usable PSP executable candidate;
5. `failed` — reserved for unexpected defects and required to carry a structured failure classification and evidence.

A normal real-game run must not leave opaque failures such as a plain exception string with no stage or reason class.

Resource analysis should similarly provide useful clustering and evidence for unknown files rather than treating every unknown file as an isolated mystery.

## Non-goals

Phase 8B does not:

- embed retail game data, saves, decrypted modules, copyrighted assets, or ISO slices in Git;
- copy GPL implementation code from PPSSPP into the MIT-licensed core;
- guess proprietary archive layouts from file extensions alone;
- claim that every proprietary resource can be decoded in one phase;
- hard-code NFS-specific file paths or format assumptions into generic PSP modules;
- replace the existing disassembler, linker, relocation, workspace, or project-generation architecture.

## Architecture

Phase 8B is split into three independently testable layers.

### 1. Executable compatibility diagnostics

Introduce a structured compatibility record around the existing game-wide module pipeline.

Each module attempt records:

- logical disc path;
- detected input/executable kind;
- pipeline stage where processing stopped;
- stable failure/recovery reason code;
- parser/recovery warnings;
- relevant PSP container metadata;
- bounded fingerprint data needed for diagnosis;
- whether the item is retryable after a toolkit upgrade;
- whether the source bytes themselves appear malformed or unsupported.

The existing broad `ParseError` / `DisassemblyError` / `ValueError` catch remains as the isolation boundary, but errors are normalized into explicit categories before being serialized.

New output:

- `metadata/module_compatibility.json`
- `reports/module_compatibility.csv`

The workspace cache version must change when compatibility semantics change so stale opaque failures are not reused.

### 2. PSP executable recovery boundary

Add a recovery interface before normal ELF/PRX analysis.

Conceptual protocol:

```python
class ExecutableRecoveryBackend(Protocol):
    name: str

    def probe(self, source: Path, model: ExecutableModel) -> RecoveryProbe: ...
    def recover(self, source: Path, output: Path, probe: RecoveryProbe) -> RecoveryResult: ...
```

The core orchestrator owns selection, provenance, output containment, hashing, verification, and failure isolation. A backend owns only the transformation from a recognized encrypted/compressed PSP executable container into candidate decrypted executable bytes.

Requirements:

- deterministic backend selection;
- minimum confidence threshold;
- no silent fallback between conflicting backends;
- recovered output must be bounded and written under the game workspace;
- recovered bytes must be re-detected and re-parsed by the existing analyzer before they are trusted;
- recovery provenance and SHA-256 identity must be recorded;
- original encrypted bytes are never overwritten;
- recovery failure never prevents other modules from being analyzed.

Licensing boundary:

- PPSSPP may be used as a behavioral/reference source;
- GPL implementation code must not be copied into the MIT core;
- if an external GPL tool/backend is used, integration must remain process-level or optional and clearly documented;
- clean-room implementations may be added only from independently documented format behavior and tests.

The first supported recovery work should target the actual PSP `~PSP` container families observed by real games, rather than attempting every historical PSP crypto/compression mode at once.

### 3. Unknown-resource family intelligence

Extend the existing Phase 7D container fingerprinting so a real game with hundreds of unknown files produces a small number of useful families.

For each unknown resource, record additional bounded evidence where safe:

- suffix;
- size bucket;
- 16-byte and 64-byte prefix fingerprints;
- bounded entropy samples;
- repeated header words;
- likely offset-table patterns;
- embedded known-resource counts;
- family membership;
- path-pattern hints.

Family grouping must remain deterministic and conservative. A family classification is evidence for later parser work, not proof of a format.

New output:

- `metadata/resource_families.json`
- `reports/resource_families.csv`

The existing `ResourceContainerParser` extension boundary remains the mechanism for real parsers. Phase 8B may add parsers only when structure is proven by evidence and bounded tests.

## Acceptance-pack workflow

The full retail ISO stays local on the user's machine.

Add a bounded compatibility evidence pack so development can proceed without uploading the game:

```bash
pspdisasm make-compat-pack ~/psp-workspaces/nfs-most-wanted \
  --output ~/nfs-most-wanted-compat.zip
```

The pack contains only deterministic metadata and tightly bounded binary evidence required to reproduce format/failure diagnosis. It must exclude full game files and obey a configurable hard size ceiling.

Expected contents include:

- module compatibility records;
- encrypted-container headers/fingerprints;
- failed-module stage/reason records;
- resource-family summaries;
- small bounded prefixes/samples only when explicitly allowed by the pack policy;
- toolkit version and source/workspace provenance.

This is the bridge between local real-game testing and repository development.

## Data flow

```text
ISO/CSO/extracted directory
        |
        v
Phase 8A workspace
        |
        +--> module candidate
        |      |
        |      v
        |   detect/analyze
        |      |
        |      +--> normal ELF/PRX --> existing placement/disasm/project/link pipeline
        |      |
        |      +--> ~PSP --> recovery registry --> recovered bytes --> verify --> normal pipeline
        |      |
        |      +--> error --> structured compatibility classification
        |
        +--> resource candidate
               |
               v
          existing detectors
               |
               +--> known resource
               |
               +--> unknown --> family profiler --> parser boundary
```

## Error handling

Unexpected exceptions must remain isolated per module/resource, but serialized results must distinguish at least:

- detection failure;
- malformed ELF;
- malformed PRX metadata;
- relocation/layout failure;
- disassembly-engine failure;
- project-generation failure;
- unsupported encrypted container;
- recovery-backend unavailable;
- recovery rejected output;
- recovery execution failure;
- containment/path failure;
- internal unexpected failure.

Containment/security violations remain game-level integrity failures where continuing could write outside the workspace.

## Testing strategy

Implementation remains test-driven.

### Unit tests

- stable compatibility reason mapping;
- deterministic serialization;
- recovery backend selection and confidence ties;
- output path containment;
- recovered-output verification;
- failure isolation;
- resource family fingerprints/grouping;
- pack size and path safety.

### Synthetic integration tests

Use generated ELF/PRX/container fixtures only. No commercial game data is committed.

Test full flows for:

- normal decrypted module;
- recognized encrypted module with no backend;
- successful synthetic recovery backend;
- backend failure;
- invalid recovered bytes;
- malformed candidate with structured failure reason;
- mixed game where one bad module does not abort good modules;
- deterministic unknown-resource family grouping.

### Real-game acceptance test

NFS Most Wanted 5-1-0 is the first local acceptance target.

The first acceptance loop is:

1. rerun the existing workspace with Phase 8B diagnostics;
2. create a compatibility pack;
3. classify all 6 current opaque failures;
4. inventory the 9 `~PSP` container variants;
5. implement generic recovery for the observed recoverable family/families;
6. rerun until no executable candidate remains an unexplained `failed` result;
7. inspect resource-family output and implement only structurally proven parser(s).

The repository's automated CI does not require the retail ISO. Live acceptance is documented separately from synthetic CI.

## Compatibility targets

Phase 8B is considered complete when:

- no module failure is represented solely by an unclassified exception string;
- encrypted modules carry precise recovery metadata and supported ones can flow back into ordinary analysis automatically;
- the NFS acceptance run has zero unexplained executable failures;
- unknown resources are deterministically grouped into evidence-backed families;
- a bounded compatibility pack can reproduce the evidence needed for further toolkit work without transferring the full game;
- all new behavior is covered by fixture-based tests and the repository payload guard remains clean.

The target is increased generic PSP compatibility, not a particular percentage of NFS resources recognized. Resource parsers are added only when their formats are actually understood.
