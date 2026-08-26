# Phase 4 m2c Assisted Decompilation Design

## Goal

Add an assisted single-function C decompilation workflow to `pspdisasm` that consumes a Phase 3 project, invokes the supplied GPLv3 `m2c` tool strictly out-of-process, preserves its generated C, and records PSP-specific limitations without changing the MIT licensing boundary of the core package.

## Scope

Phase 4 adds `pspdisasm decompile PROJECT FUNCTION`. It operates on an already-generated project and its `metadata/functions.json`; it does not rerun ELF analysis or instruction discovery. The function may be selected by exact symbol name or numeric address. The first release is intentionally single-function; batch scheduling and recompilation matching belong to later phases.

## m2c boundary

`m2c` remains an external executable/script and is never imported or copied into `pspdisasm`. The adapter resolves an explicit `--m2c PATH`, then `PSPDISASM_M2C`, then an `m2c` executable on `PATH`. A `.py` path is launched with the current Python interpreter. Failure to locate m2c is a typed `DecompilerUnavailableError` with installation/configuration guidance.

The invocation uses `-t mipsel-gcc-c`, `--valid-syntax`, `--deterministic-vars`, `--no-cache`, `--globals=used`, `-f FUNCTION`, optional repeated `--context`, and a temporary assembly file containing the exact Phase 2 function assembly. Context files are passed through unchanged and must already satisfy m2c's own preprocessing requirements.

## PSP-specific correctness behavior

m2c supports little-endian MIPS O32 but does not fully understand PSP Allegrex/VFPU extensions. The adapter must not rewrite those opcodes into invented semantics. If m2c emits `M2C_ERROR(...)`, the generated C is preserved as an assisted draft and the adapter extracts unknown-instruction markers into `unsupported_instructions` plus human-readable warnings. A successful m2c process containing such markers is still a successful assisted decompilation with warnings, not a matching/source-correctness claim.

A non-zero m2c process result is treated as a decompilation failure. Its stderr/stdout summary is surfaced through `DecompilationError`; a failed run must not replace an existing successful C artifact.

## Project artifacts

For `func_08800028`, the default outputs are:

- `asm/nonmatchings/func_08800028.s` — exact assembly submitted to m2c.
- `src/nonmatching/func_08800028.c` — m2c-generated C draft.
- `metadata/decompilations/func_08800028.json` — deterministic metadata containing function identity, target, artifact paths, m2c version when detectable, warnings, and unsupported instructions.

`src/nonmatching` and `metadata/decompilations` are created on demand. An explicit `--output PATH` overrides only the C output path; the assembly and metadata remain project-relative so the run stays traceable.

## Function selection

The project loader validates that `metadata/functions.json` is a JSON list with the expected Phase 2 fields. Exact symbol-name match is preferred. Numeric selectors accept decimal or `0x` hexadecimal and resolve by address. Missing functions and duplicate ambiguous names/addresses produce `DecompilationError` rather than guessing.

## Public interfaces

`decompile_project_function(project_dir, selector, *, m2c_path=None, contexts=(), output_path=None, target="mipsel-gcc-c") -> DecompilationResult`

`DecompilationResult` records project directory, function name/address, C output path, assembly path, metadata path, backend version, target, warnings, and unsupported instructions.

## CLI

```
pspdisasm decompile game_decomp func_08800028
pspdisasm decompile game_decomp 0x08800028 --m2c /path/to/m2c.py
pspdisasm decompile game_decomp func_08800028 --context include/context.i
```

The CLI prints the selected function, C path, metadata path, and warnings. Existing `analyze`, `disasm`, and `project` behavior remains unchanged.

## Testing

Tests cover function lookup by name/address, missing/corrupt project metadata, command construction and external-process failure using a controlled fake backend, output/metadata materialization, unsupported-opcode warning extraction, CLI behavior, and one integration test against the supplied `m2c-master` source showing that a generic fixture function decompiles to `return 1;`. The entire Phase 1-3 suite must remain green with supplied Rabbitizer/spimdisasm sources on `PYTHONPATH`.

## Deliberate limitations

- No semantic lowering of Allegrex/VFPU-only instructions.
- No automatic header/type context generation yet.
- No batch decompilation.
- No compiler invocation or byte matching.
- No asm-differ integration; that is Phase 5.
