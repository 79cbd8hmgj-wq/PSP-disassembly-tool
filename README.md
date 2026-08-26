# pspdisasm

`pspdisasm` is a PSP-focused executable-analysis, disassembly, decompilation, and matching toolkit. It adds PSP-specific container/PRX intelligence around the Decompollaborate ecosystem instead of merging the upstream projects into one fork.

## Current status: Phase 6A

The toolkit currently covers the original five workflow layers plus the first advanced-analysis layer:

### Phase 1 — PSP executable intelligence

- Detect raw ELF32 and `~PSP` inputs.
- Parse ELF32 headers, program headers, sections, and PSP PRX type `0xFFA0`.
- Parse `sceModuleInfo`, import/export libraries, unresolved NIDs, and standard PSP/MIPS relocations.
- Detect compressed `PT_PRXRELOC2` streams without pretending to decode them.
- Parse the outer `~PSP` header and stop safely at the encryption/decompression boundary.

### Phase 2 — Allegrex/VFPU disassembly

- Use Rabbitizer with `R4000ALLEGREX` for PSP instruction decoding, including VFPU.
- Use spimdisasm for function discovery, symbols, calls, branches, data references, and string references.
- Emit normalized function/instruction/symbol/reference/string metadata and deterministic assembly.

### Phase 3 — Splat workspace generation

- Flatten allocated ELF sections into a VRAM-linear `target.bin`.
- Generate PSP/GCC/little-endian `splat.yaml` configuration.
- Seed discovered functions, data, entrypoint, and string symbols.
- Create reusable `metadata/`, `asm/`, `src/`, `build/`, `assets/`, and `reports/` directories.

### Phase 4 — m2c-assisted C drafts

- Select a function by name or address from a Phase 3 project.
- Run m2c strictly out-of-process.
- Preserve the assembly submitted to m2c and write C drafts under `src/nonmatching/`.
- Record unsupported Allegrex/VFPU instructions instead of inventing semantics.

### Phase 5 — asm-differ matching workflow

- Select a Phase 3/4 function by name or address.
- Synthesize a minimal little-endian MIPS ELF reference object directly from the original Phase 2 instruction words.
- Optionally run an explicit build command to create the current candidate object.
- Run asm-differ strictly out-of-process in object/JSON mode.
- Normalize raw asm-differ score data into a 0–100 similarity percentage plus matching/changed/added/removed row counts.
- Persist the synthesized reference object, normalized matching metadata, and the complete raw asm-differ JSON report.
- Preserve previous successful reports when a build or backend invocation fails.

### Phase 6A — advanced program analysis

- Normalize direct calls and spimdisasm-resolved indirect `jalr` calls into a function-to-function call graph.
- Expose accepted spimdisasm jump-table discoveries without inventing tables from arbitrary pointer-looking data.
- Decode consecutive little-endian jump-table entries only while they resolve to executable mapped sections.
- Assign deterministic `0.00`–`1.00` function-boundary confidence scores with human-readable evidence.
- Reward ELF-entry, PSP import/export seeds, incoming calls, and valid/implemented instruction bodies while penalizing invalid or unimplemented instructions.
- Emit standalone call-graph, jump-table, confidence, and combined advanced-analysis JSON reports during project generation.

Phase 6B will build on this normalized layer with NID-to-name databases, cross-module relationships, symbol propagation, richer data typing, and later asset discovery.

## Installation

Basic PSP executable parsing requires only the core package dependencies:

```bash
python -m pip install -e .
```

Install Phase 2 analysis engines with:

```bash
python -m pip install -e '.[analysis]'
```

Phase 4 and Phase 5 intentionally keep their external tools out of the package dependency graph:

- m2c must be supplied separately for `decompile`.
- asm-differ must be supplied separately for `match`.
- a MIPS-capable objdump is required for `match`; `psp-objdump` is preferred.
- the correct PSP compiler/build toolchain remains project-specific and is not bundled.

## Commands

### Analyze

```bash
pspdisasm analyze decrypted_EBOOT.BIN
pspdisasm analyze module.prx --json executable.json
```

### Disassemble

```bash
pspdisasm disasm decrypted_EBOOT.BIN
pspdisasm disasm decrypted_EBOOT.BIN --asm-dir asm --json disassembly.json
```

### Generate a decompilation project

```bash
pspdisasm project decrypted_EBOOT.BIN game_decomp
```

Typical generated structure:

```text
game_decomp/
├── splat.yaml
├── target.bin
├── config/
├── metadata/
│   ├── executable.json
│   ├── disassembly.json
│   ├── functions.json
│   ├── symbols.json
│   ├── references.json
│   ├── strings.json
│   ├── advanced.json
│   ├── callgraph.json
│   ├── jump_tables.json
│   └── function_confidence.json
├── asm/
│   └── nonmatchings/
├── src/
├── build/
├── assets/
└── reports/
```

Phase 6A runs automatically during project generation. The same pure analysis entry point is also available to Python callers as `pspdisasm.analyze_advanced(model, disassembly)`.

### Generate an assisted C draft

```bash
pspdisasm decompile game_decomp func_08812340 --m2c /path/to/m2c.py
```

or by address:

```bash
pspdisasm decompile game_decomp 0x08812340 --m2c /path/to/m2c.py
```

m2c can also be resolved from `PSPDISASM_M2C` or an `m2c` executable on `PATH`.

### Match a recompiled function

Compile the edited C with the intended PSP compiler/toolchain, then point `pspdisasm` at the resulting object:

```bash
pspdisasm match game_decomp func_08812340 \
  --object build/src/nonmatching/func_08812340.o \
  --asm-differ /path/to/asm-differ/diff.py \
  --objdump /path/to/psp-objdump
```

Run a build command immediately before matching:

```bash
pspdisasm match game_decomp func_08812340 \
  --object build/src/nonmatching/func_08812340.o \
  --build-command "make build/src/nonmatching/func_08812340.o" \
  --asm-differ /path/to/diff.py \
  --objdump /path/to/psp-objdump
```

The build command is parsed into argv and executed without `shell=True`.

Backend paths can also be configured through:

```text
PSPDISASM_ASM_DIFFER=/path/to/diff.py
PSPDISASM_OBJDUMP=/path/to/psp-objdump
```

If no explicit objdump is supplied, `pspdisasm` searches for `psp-objdump`, then `mipsel-linux-gnu-objdump`, then `objdump`.

Additional matching options:

```text
--reference-object PATH   use a known original object instead of synthesizing one
--section SECTION         compare a section other than .text
--ignore-large-imms       pass asm-differ's large-immediate normalization option
--timeout SECONDS         build/backend timeout; default 120
```

## Phase 5 artifacts

For an automatically synthesized reference object:

```text
game_decomp/
├── build/matching/reference/func_08812340.o
├── metadata/matching/func_08812340.json
└── reports/matching/func_08812340.asm-differ.json
```

The normalized metadata records:

- function name/address/size/section;
- candidate and reference object paths;
- asm-differ version when detectable;
- objdump path;
- build command when used;
- raw score and asm-differ maximum score;
- normalized similarity percentage;
- matching, changed, added, and removed row counts;
- matching settings and warnings.

An asm-differ raw score of zero maps to `100.00%` similarity. Because asm-differ penalties can exceed its deletion-based `max_score`, normalized similarity is clamped to the 0–100 range while the original raw values remain preserved.

## Phase 6A artifacts

Project generation now emits:

- `metadata/advanced.json` — complete normalized advanced-analysis result;
- `metadata/callgraph.json` — direct and resolved-indirect function edges;
- `metadata/jump_tables.json` — accepted table address, source jump site, owning function, and executable targets;
- `metadata/function_confidence.json` — score and evidence for each discovered function boundary.

The advanced layer consumes only normalized PSP executable/disassembly models. It does not import spimdisasm or Rabbitizer directly, keeping upstream-engine access isolated inside the Phase 2 adapter.

## Reference-object design and limitation

Phase 5 builds the reference `.o` directly from the exact instruction words already stored in `metadata/functions.json`. The generated object is ELF32 little-endian `ET_REL`/`EM_MIPS` and contains `.text`, `.symtab`, `.strtab`, and `.shstrtab` with a global function symbol.

The synthesized object does **not yet synthesize MIPS relocation records**. A function containing calls or global/data references may therefore receive a pessimistic score when the newly compiled object contains symbolic relocations. If the Phase 2 reference metadata shows external references, `pspdisasm` records this limitation as a warning. A real original/reference object can be supplied with `--reference-object` when one exists.

## Correct compiler requirement

A matching score is meaningful only when the candidate is compiled with the appropriate PSP compiler version, ABI, optimization settings, and project flags. `pspdisasm` deliberately does not choose or emulate that compiler. Phase 5 owns orchestration and reporting; compiler identification/reproduction is a separate project concern.

## Upstream tool roles

- **Rabbitizer** — PSP Allegrex/VFPU instruction decoding.
- **spimdisasm** — MIPS/Allegrex function, symbol, and reference analysis.
- **Splat** — PSP-aware decompilation project conventions and splitting workflow.
- **m2c** — optional assembly-to-C assistance, kept out-of-process because of GPLv3.
- **asm-differ** — original-vs-recompiled function diff/scoring backend, kept out-of-process.

## Current limitations

- No PSP cryptographic decryption.
- No GZIP/KL4E/2RLZ decompression of encrypted `~PSP` bodies.
- No `PT_PRXRELOC2` decompression/application yet.
- No NID-to-name database yet.
- No ISO/CSO filesystem extraction yet.
- m2c does not understand every PSP Allegrex/VFPU instruction.
- Synthesized Phase 5 reference objects do not yet reproduce original relocation tables.
- No automatic PSP compiler/version identification yet.
- No automatic high-level type/header reconstruction yet.

## Development

Run the test suite with the Phase 2 analysis dependencies available:

```bash
PYTHONPATH=src python -m pytest -q
```

The repository test workflow installs the analysis extra and runs the complete synthetic suite on pushes and pull requests. The tests use synthetic PSP-like ELF/PRX structures; no commercial game data is included.
