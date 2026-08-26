# Phase 6C Data Typing and Reference Intelligence Design

## Goal

Add a conservative, explainable data-typing layer above the existing PSP parser/disassembler so generated projects can distinguish strings, pointers, function pointers, pointer tables, jump tables, and probable structured data without treating arbitrary 32-bit values as addresses.

The layer must consume normalized Phase 1/2 metadata plus the already parsed ELF image. It must not import spimdisasm or Rabbitizer directly and must not mutate low-level `ExecutableModel`, `DisassemblyResult`, or existing Phase 6B NID-link records.

## Architectural position

Phase 6C is a new pure-analysis module, tentatively `pspdisasm.typing`, with one public entry point:

```python
analyze_data_types(model, disassembly, elf) -> DataTypingResult
```

Inputs:

- `ExecutableModel`: PSP imports/exports, relocations, module metadata, section metadata.
- `DisassemblyResult`: functions, symbols, references, strings, jump tables.
- `ElfImage`: raw bytes and virtual-address mapping for safe aligned word reads.

Outputs are normalized dataclasses only. Project generation serializes them separately.

## Core records

Add normalized records to `model.py`:

- `TypedFieldRecord(offset, type_name, target_address, confidence, evidence)`
- `DataTypeRecord(address, section, type_name, size, count, element_type, confidence, evidence, fields)`
- `TypedReferenceRecord(source_address, target_address, kind, source_function, target_section, target_type, confidence, evidence)`
- `TypedCallEdge(source_function, target_function, source_address, target_address, kind, evidence)`
- `DataTypingResult(source_name, data_types, typed_references, call_edges, warnings)`

`type_name` values in Phase 6C are limited to:

- `string`
- `pointer`
- `function_pointer`
- `pointer_table`
- `function_pointer_table`
- `jump_table`
- `struct_candidate`
- `array_candidate`

The `*_candidate` names are deliberate: Phase 6C does not claim recovered C types or field names.

## Evidence model

Every inferred type must carry both a deterministic confidence score and human-readable evidence strings.

Strong evidence:

- exact address already present in `DisassemblyResult.strings`;
- exact jump-table address already accepted by Phase 6A/spimdisasm;
- 32-bit value resolves to the exact start of a discovered function;
- 32-bit value resolves to an exact PSP export-function address;
- a relocation record can be safely mapped to the candidate storage slot.

Supporting evidence:

- target maps into an allocated, file-backed ELF section;
- target matches an existing normalized data symbol;
- target matches a known string start;
- multiple consecutive aligned entries form the same pointer pattern;
- repeated fixed-width records exhibit the same typed-field signature.

A raw integer whose numeric value merely falls inside mapped memory is not enough on its own.

## Relocation safety rules

Current Phase 1 stores standard PSP/MIPS Type-A relocation records but does not apply them, and `PT_PRXRELOC2` remains undecoded.

Phase 6C may use a relocation as corroborating evidence only when its `offset` can be mapped unambiguously to a file-backed allocated address in the current ELF image.

If a relocation offset cannot be mapped safely:

- do not guess segment-relative semantics;
- do not use it as pointer evidence;
- add one deterministic warning describing the skipped relocation class/location.

`PT_PRXRELOC2` data is completely out of scope for Phase 6C and remains a later phase.

## Leaf type inference

### Strings

Every existing `StringRecord` becomes a `DataTypeRecord(type_name="string")` at confidence `1.00`.

No new free-form string scanner is introduced in Phase 6C. This keeps string typing tied to the existing referenced-string detector.

### Function pointers

An aligned 4-byte data slot is a `function_pointer` only when:

1. the slot lies in an allocated, file-backed, non-executable section;
2. its little-endian 32-bit value equals an exact discovered function start or exact PSP exported function address; and
3. at least one corroborator exists:
   - safely mapped relocation at the slot; or
   - the slot is part of a qualifying repeated pointer-table pattern; or
   - the slot address itself is an existing data symbol/reference anchor.

Confidence:

- `1.00` with safely mapped relocation plus exact function target;
- `0.95` with exact function target plus normalized symbol/reference anchor;
- `0.90` when admitted only through a repeated table pattern.

### Data pointers

An aligned 4-byte data slot is a `pointer` only when its value maps to an allocated section and one of these is true:

- the slot has safely mapped relocation evidence;
- the target is an exact known string/data symbol/jump-table address and the slot is an existing symbol/reference anchor;
- the slot belongs to a qualifying repeated pointer-table pattern.

A single unreferenced integer pointing somewhere into `.data`/`.rodata` is never emitted as a pointer.

## Pointer-table inference

Only aligned words in allocated, file-backed, non-executable sections are eligible.

A run becomes a table when:

- there are at least 3 consecutive pointer/function-pointer entries; or
- there are at least 2 consecutive entries and every entry has safely mapped relocation evidence.

The run stops at the first non-qualifying word, section boundary, or overlap with an already accepted string/jump table.

Classification:

- all entries target functions -> `function_pointer_table`;
- otherwise -> `pointer_table`.

The table record includes `size = count * 4`, `count`, and `element_type`.

Confidence is the minimum confidence of its admitted entries, capped at `0.95` unless every entry is relocation-backed.

## Existing jump tables

Every accepted Phase 6A `JumpTableRecord` becomes a `DataTypeRecord(type_name="jump_table")` at confidence `1.00`.

Phase 6C does not rediscover or widen jump tables. Existing spimdisasm acceptance remains authoritative.

## Structured-data candidates

Phase 6C may produce low-confidence structural candidates, but only from already anchored data.

### Data anchors

A non-executable data address is an anchor when it is one of:

- target of a normalized code/data reference;
- existing normalized data symbol;
- PSP imported/exported variable address;
- start of an accepted pointer/function-pointer table.

### Struct candidates

At an anchor, inspect at most the first 64 bytes, stopping at a section boundary or another stronger typed object.

Emit `struct_candidate` only when:

- at least two distinct aligned fields in the bounded region have accepted leaf types (`pointer` or `function_pointer`); and
- the object is not already classified as a pointer table or jump table.

The record stores field offsets and their leaf-type evidence. Confidence starts at `0.65`, rises to `0.75` if one field is relocation-backed, and to `0.80` if two or more fields are relocation-backed. It never exceeds `0.80` in Phase 6C.

### Array candidates

From an anchored struct candidate, test fixed record sizes in this deterministic set:

`8, 12, 16, 20, 24, 32, 48, 64` bytes.

Emit `array_candidate` only when at least two consecutive records share the same accepted typed-field offset/type signature and remain within the same section.

The array record includes element size, count, and a copy of the common field signature. Confidence is `min(struct confidence values) - 0.05`, clamped to `0.60..0.75`.

No scalar-only arrays are inferred in Phase 6C.

## Typed references

Every existing normalized `ReferenceRecord` receives a parallel `TypedReferenceRecord`.

If its target address matches an inferred `DataTypeRecord`, attach that type and confidence. Otherwise use `target_type="unknown"`, confidence `0.00`, and empty evidence.

This preserves all original references and avoids changing Phase 2 serialization.

## Function-pointer call enrichment

Phase 6C must not invent calls merely because a function address appears in data.

A new `TypedCallEdge` is emitted only when an existing `ReferenceRecord(kind="indirect_call")` targets a data slot that Phase 6C has classified as a `function_pointer`, and the slot's stored value resolves to an exact discovered function start.

The edge kind is `typed_indirect` and its evidence must include both the existing indirect-call record and the function-pointer classification.

Direct calls and already-resolved Phase 6A indirect calls remain owned by `advanced.py`; Phase 6C call edges are additive metadata.

## Conflict and overlap rules

Type precedence at the same address is:

1. `string`
2. `jump_table`
3. `function_pointer_table`
4. `pointer_table`
5. `function_pointer`
6. `pointer`
7. `array_candidate`
8. `struct_candidate`

Higher-precedence types suppress lower-precedence records that begin at the same address.

Accepted strings, jump tables, and pointer tables also reserve their byte ranges so lower-confidence structured candidates cannot overlap them.

When two same-precedence candidates conflict, choose higher confidence; ties resolve deterministically by `(type_name, size, evidence)` lexical ordering and emit a warning.

## Project integration

`build_project_artifacts` runs Phase 6C after Phase 6A and optional Phase 6B NID resolution.

`generate_project` writes:

- `metadata/data_typing.json` — complete `DataTypingResult`;
- `metadata/data_types.json` — inferred data types only;
- `metadata/typed_references.json` — references annotated with inferred target type;
- `metadata/typed_callgraph.json` — Phase 6C typed-indirect edges.

Existing metadata files remain unchanged for compatibility.

## Symbol propagation into generated projects

Phase 6C may add autogenerated names for strong inferred objects only when the address has no stronger existing name from:

1. ELF entry point;
2. existing string symbol;
3. curated/non-autogenerated discovered function or symbol;
4. Phase 6B NID propagation.

Minimum confidence for symbol emission is `0.90`.

Fallback prefixes:

- `FUNCPTR_XXXXXXXX`
- `PTR_XXXXXXXX`
- `FUNCPTRTBL_XXXXXXXX`
- `PTRTBL_XXXXXXXX`

`struct_candidate` and `array_candidate` never receive generated names in Phase 6C because their maximum confidence is below the symbol-emission threshold.

Do not invent new Splat `type:` directives. Existing supported comments such as `type:func` and `type:asciz` remain untouched; detailed Phase 6C type facts live in JSON metadata.

## Public API and version

Export `analyze_data_types` from `pspdisasm.__init__` and bump the package version from `0.7.0` to `0.8.0` once implementation is complete.

No new CLI command is required. Phase 6C runs automatically during `project` generation and is available directly through the Python API.

## Error handling

The type engine is best-effort analysis.

- malformed/out-of-range data reads produce warnings and skip only the affected candidate;
- unmappable relocations are skipped, not fatal;
- NOBITS sections are never read as bytes;
- section-boundary checks are mandatory for every word/table/record read;
- analysis order and output ordering must be deterministic.

A core parser/disassembler failure remains fatal through the existing error path.

## Testing strategy

Use synthetic ELF/PRX fixtures and pure dataclass fixtures. Required RED -> GREEN coverage:

1. existing `StringRecord` -> `string` at confidence `1.00`;
2. existing jump table -> `jump_table` at confidence `1.00`;
3. relocation-backed pointer -> accepted;
4. relocation-backed exact function target -> `function_pointer`;
5. arbitrary mapped-looking integer without corroboration -> rejected;
6. unaligned pointer-looking bytes -> rejected;
7. 3-entry pointer table -> accepted;
8. 2-entry table without relocation on both slots -> rejected;
9. 2-entry relocation-backed table -> accepted;
10. homogeneous function targets -> `function_pointer_table`;
11. section-boundary truncation stops table safely;
12. `struct_candidate` requires at least two accepted typed fields;
13. repeated field signatures -> `array_candidate`;
14. stronger string/jump-table/table typing suppresses overlapping weaker candidates;
15. typed references preserve all original reference identities;
16. typed-indirect call edge requires an existing `indirect_call` plus function-pointer slot;
17. project generation emits all four Phase 6C metadata files;
18. strong type-generated symbols do not overwrite curated/NID/string/function names;
19. package exports API and reports version `0.8.0`;
20. complete Phase 1-6B regression suite remains green.

## Explicit non-goals

Phase 6C does not:

- decode/apply `PT_PRXRELOC2`;
- recover exact C struct names, field names, enums, unions, or scalar signedness;
- infer scalar-only arrays;
- mutate Phase 2 symbols/functions/references;
- treat every mapped-looking word as a pointer;
- create speculative call-graph edges from data tables alone;
- extract ISO/CSO files or game assets.

Those remain later phases.
