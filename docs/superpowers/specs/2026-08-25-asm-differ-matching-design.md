# Phase 5 asm-differ Matching Workflow Design

## Goal

Add a repeatable single-function matching workflow to `pspdisasm` that compares original PSP Allegrex instructions with a newly compiled object using external `asm-differ`, without bundling a compiler or asm-differ itself.

## Architecture

Phase 5 consumes the Phase 3 workspace and Phase 2 instruction words. For a selected function, `pspdisasm` synthesizes a minimal ELF32 little-endian MIPS relocatable reference object containing the original instruction words and a function symbol. The caller supplies the candidate object, optionally after an explicit build command. `pspdisasm` generates a temporary `diff_settings.py`, invokes external `asm-differ` in object/JSON mode, normalizes the result, and persists stable project metadata plus the raw backend report.

`asm-differ` remains out-of-process. The core package does not depend on its Python modules or license, and does not assume a compiler. Exact matching therefore depends on the caller using the correct PSP compiler/toolchain and flags.

## Inputs

Required:

- Phase 3 project directory containing `metadata/functions.json`.
- Function selector by name or address.
- Candidate object path containing the compiled function symbol.

Optional:

- Explicit build command, executed without a shell from the project directory before matching.
- Explicit asm-differ executable or `diff.py` path.
- Explicit objdump executable.
- Explicit reference object instead of the synthesized reference object.
- Section override, default `.text`.
- asm-differ immediate-normalization flag.

Backend resolution order:

- asm-differ: explicit path, `PSPDISASM_ASM_DIFFER`, `asm-differ` on `PATH`.
- objdump: explicit path, `PSPDISASM_OBJDUMP`, `psp-objdump`, `mipsel-linux-gnu-objdump`, then `objdump` on `PATH`.

## Reference Object

The synthesized object is ELF32, little-endian, `ET_REL`, `EM_MIPS`, with `.text`, `.symtab`, `.strtab`, and `.shstrtab`. `.text` is built directly from the `word` fields in the Phase 2 instruction records. The function symbol covers the entire text section.

This reference object deliberately does not synthesize MIPS relocation records in Phase 5. Functions with calls/global references can therefore score pessimistically compared with candidate objects that contain symbolic relocations. The report records this limitation when the selected function has discovered external references.

## asm-differ Invocation

Use object mode and JSON output:

`FUNCTION -o -f CANDIDATE.o -F REFERENCE.o --format json --algorithm difflib --no-pager --no-line-numbers -j .text`

The generated `diff_settings.py` sets `arch = "mipsel"`, the resolved objdump executable, and the project source directory. `difflib` is selected so Phase 5 does not require the optional Python Levenshtein module merely to request a one-shot report.

## Result Model

Persist:

- backend name/version;
- function name/address;
- candidate and reference object paths;
- raw score and maximum score;
- normalized similarity percentage, clamped to 0–100, with exact match = 100%;
- matching, changed, added, and removed row counts;
- build command when used;
- warnings;
- raw asm-differ JSON report path.

Artifacts:

- `build/matching/reference/<function>.o`
- `metadata/matching/<function>.json`
- `reports/matching/<function>.asm-differ.json`

## Failure Semantics

Missing backend/tool paths, build failures, missing candidate objects, invalid project metadata, nonzero asm-differ exits, and invalid backend JSON raise typed matching errors. A failed run must not overwrite a previous successful normalized or raw report.

## CLI

`pspdisasm match PROJECT FUNCTION --object build/foo.o [options]`

Options include `--asm-differ`, `--objdump`, `--reference-object`, `--build-command`, `--section`, `--ignore-large-imms`, and `--timeout`.

## Testing

Unit tests cover function lookup, reference-object validity, backend/path resolution, build failure safety, JSON normalization, exact/mismatch score handling, and persistence. A local integration probe exercises the supplied asm-differ source against synthesized MIPS objects; this probe is not a permanent test-suite dependency because asm-differ's runtime modules and a MIPS-capable objdump are external prerequisites.
