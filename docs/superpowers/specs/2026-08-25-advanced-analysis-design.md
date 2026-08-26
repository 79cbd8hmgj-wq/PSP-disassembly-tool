# Phase 6A Advanced Analysis Design

## Goal

Turn Phase 2's normalized Allegrex metadata into higher-level reverse-engineering intelligence without changing the upstream-engine boundary.

## Scope

Phase 6A adds three capabilities:

1. **Jump-table discovery output** — expose spimdisasm's accepted jump-table references and decode plausible table targets from mapped ELF data.
2. **Normalized call graph** — represent function-to-function edges for direct calls and resolved indirect calls, preserving the call-site address and resolution kind.
3. **Function confidence scoring** — assign a deterministic 0.0–1.0 confidence score plus evidence strings to every discovered function boundary.

NID-to-name databases, cross-module import/export linking, high-level typing, and asset discovery remain Phase 6B+ work.

## Architecture

`SpimdisasmAdapter` remains responsible only for extracting engine facts from spimdisasm/Rabbitizer. It will additionally normalize accepted jump tables and resolved indirect calls into `DisassemblyResult`.

A new pure-Python `advanced.py` layer consumes `ExecutableModel` plus `DisassemblyResult` and produces `AdvancedAnalysisResult`. This layer must not import spimdisasm or Rabbitizer, which keeps higher-level analysis deterministic and independently testable.

## Data model

Add the following normalized records:

- `JumpTableRecord(address, source_function, source_address, targets)`
- `CallGraphEdge(source_function, target_function, source_address, target_address, kind)`
- `FunctionConfidence(name, address, score, evidence)`
- `AdvancedAnalysisResult(source_name, call_edges, function_confidence, jump_tables, warnings)`

`kind` for call-graph edges is `direct` or `indirect`.

## Jump-table rules

spimdisasm's `referencedJumpTableOffsets` is the acceptance signal. For each accepted table:

- identify the instruction that ultimately jumps through the table;
- resolve the table address into the ELF image;
- read little-endian 32-bit entries starting at the table address;
- accept consecutive entries only while they point into executable mapped sections;
- stop at the first non-executable pointer or after 256 entries;
- retain tables with at least two targets;
- deduplicate identical `(table address, source function)` records.

The tool must never invent jump-table targets when the bytes do not form plausible executable addresses.

## Call graph rules

Build direct edges from normalized `ReferenceRecord(kind="call")` entries. Add indirect edges from resolved indirect calls exposed by spimdisasm. Resolve target function names by exact function start address. Calls whose targets are not known function starts remain in low-level references but are omitted from the function-to-function graph.

Edges are deduplicated by source function, target function, call site, target address, and kind.

## Confidence scoring

Start each function at `0.50` and apply deterministic evidence:

- `+0.25` if its address is the ELF entry point;
- `+0.20` if the function start is seeded by a PSP import/export function record;
- `+0.10` if at least one other function directly or indirectly calls it;
- `+0.05` if it has at least two instructions and all instructions are valid;
- `+0.05` if all instructions are implemented by Rabbitizer;
- `-0.20` if any instruction is invalid;
- `-0.10` if any instruction is unimplemented.

Clamp scores to `0.0..1.0`. Evidence strings must state which rules fired so the score is explainable.

## Output integration

`generate_project` will write:

- `metadata/advanced.json`
- `metadata/callgraph.json`
- `metadata/jump_tables.json`
- `metadata/function_confidence.json`

The Phase 2 metadata files remain unchanged and continue to be valid inputs for existing Phase 3–5 workflows.

## Testing

Tests use only synthetic PSP-like ELF/PRX fixtures. Add focused unit tests for call-edge normalization, confidence scoring, accepted/rejected jump-table target decoding, and project metadata emission. Existing Phase 1–5 tests must remain green.
