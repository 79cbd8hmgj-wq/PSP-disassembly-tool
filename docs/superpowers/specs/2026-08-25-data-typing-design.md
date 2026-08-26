# Phase 6C Data Typing and Reference Intelligence Design

## Goal

Add a conservative, explainable data-typing layer above the existing PSP parser/disassembler so generated projects can distinguish strings, pointers, function pointers, pointer tables, jump tables, and probable structured data without treating arbitrary 32-bit values as addresses.

The layer must consume normalized Phase 1/2 metadata plus the already parsed ELF image. It must not import spimdisasm or Rabbitizer directly and must not mutate low-level `ExecutableModel`, `DisassemblyResult`, or existing Phase 6B NID-link records.

## Architectural position

Phase 6C is a new pure-analysis module, `pspdisasm.data_typing`, with one public entry point:

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
- `DataTypeRecord(address, section, type_name, size, target_address, count, element_type, element_size, confidence, evidence, fields)`
- `TypedReferenceRecord(source_address, target_address, kind, source_function, target_section, target_type, confidence, evidence)`
- `TypedCallEdge(source_function, target_function, source_address, target_address, kind, evidence)`
- `DataTypingResult(source_name, data_types, typed_references, call_edges, warnings)`

Optional scalar fields use `None` when not applicable. For example, standalone pointers set `target_address`; tables set `count` and `element_size`; strings and jump tables do not need a pointer target.

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

Phase 6C uses only the direct virtual-address interpretation of a relocation's `offset`. A relocation corroborates a slot only when that exact `offset` lies inside an allocated, file-backed ELF section and maps through the current `ElfImage`.

If the direct virtual-address interpretation does not map safely:

- do not guess segment-relative semantics;
- do not use it as pointer evidence;
- add one deterministic warning per distinct skipped relocation `(source, type_name, offset)`.

`PT_PRXRELOC2` data is completely out of scope for Phase 6C and remains a later phase.

## Deterministic analysis pipeline

The engine runs in this order:

1. seed exact existing strings and accepted jump tables;
2. normalize safely mappable relocation-slot evidence;
3. build exact function/export/string/data-symbol/reference anchors;
4. scan aligned non-executable file-backed data for qualifying pointer-table runs;
5. emit accepted pointer/function-pointer tables and suppress their child slot records from top-level output;
6. infer remaining standalone pointer/function-pointer slots from relocation or anchor evidence;
7. infer struct candidates from anchored leaf fields;
8. infer repeated struct signatures as array candidates;
9. resolve overlaps/conflicts;
10. annotate existing references and derive typed-indirect call edges.

This order removes the circularity between table evidence and leaf-pointer admission while keeping each decision reproducible.

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
   - the slot is part of an accepted repeated pointer-table pattern; or
   - the slot address itself is an existing data symbol/reference anchor.

Confidence:

- `1.00` with safely mapped relocation plus exact function target;
- `0.95` with exact function target plus normalized symbol/reference anchor;
- `0.90` when admitted only through an accepted repeated table pattern.

The record stores the function address in `target_address`.

### Data pointers

An aligned 4-byte data slot is a `pointer` only when its value maps to an allocated section and one of these is true:

- the slot has safely mapped relocation evidence;
- the target is an exact known string/data symbol/jump-table address and the slot is an existing symbol/reference anchor;
- the slot belongs to an accepted repeated pointer-table pattern.

A single unreferenced integer pointing somewhere into `.data`/`.rodata` is never emitted as a pointer.

The pointed-to address is stored in `target_address`.

## Pointer-table inference

Only aligned words in allocated, file-backed, non-executable sections are eligible.

A run becomes a table when either:

- it contains at least 3 consecutive mapped pointer-like values **and** the run has at least one safely mapped relocation-backed slot or at least two entries target exact known function/string/data-symbol/jump-table identities; or
- it contains at least 2 consecutive entries and every slot has safely mapped relocation evidence.

The run stops at the first non-mapped word, section boundary, or overlap with an already accepted string/jump table.

Classification:

- all entries target exact functions/PSP function exports -> `function_pointer_table`;
- otherwise -> `pointer_table`.

The table record includes `size = count * 4`, `count`, `element_size = 4`, and `element_type` (`function_pointer` for a homogeneous function table, otherwise `pointer`).

Confidence is the minimum confidence of its admitted entries, capped at `0.95` unless every entry is relocation-backed.

Once a table is accepted, its individual child pointer slots remain available internally as field evidence but are not duplicated as top-level `DataTypeRecord` entries.

## Existing jump tables

Every accepted Phase 6A `JumpTableRecord` becomes a `DataTypeRecord(type_name="jump_table")` at confidence `1.00`.

Its `size` is `len(targets) * 4`, `count` is `len(targets)`, and `element_size = 4`.

Phase 6C does not rediscover or widen jump tables. Existing spimdisasm acceptance remains authoritative.

## Structured-data candidates

Phase 6C may produce low-confidence structural candidates, but only from already anchored data.

### Data anchors

A non-executable data address is an anchor when it is one of:

- target of a normalized `ReferenceRecord` with kind `data` or `pointer`;
- existing normalized non-code data symbol;
- PSP imported/exported variable address;
- start of an accepted pointer/function-pointer table.

### Struct candidates

At an anchor, inspect at most the first 64 bytes, stopping at a section boundary or another stronger typed object.

Emit `struct_candidate` only when:

- at least two distinct aligned fields in the bounded region have accepted leaf types (`pointer` or `function_pointer`); and
- the object is not already classified as a pointer table or jump table.

The record stores each accepted field as a `TypedFieldRecord` with field offset and target address. Confidence starts at `0.65`, rises to `0.75` if one field is relocation-backed, and to `0.80` if two or more fields are relocation-backed. It never exceeds `0.80` in Phase 6C.

`size` is the smallest 4-byte-aligned span that contains all accepted fields, capped at 64 bytes.

### Array candidates

From an anchored struct candidate, test fixed record sizes in this deterministic set:

`8, 12, 16, 20, 24, 32, 48, 64` bytes.

Emit `array_candidate` only when at least two consecutive records share the same accepted typed-field offset/type signature and remain within the same section.

The array record sets `element_type="struct_candidate"`, `element_size` to the chosen fixed record size, `count` to the repeated record count, and `size = element_size * count`. Its `fields` contain the common element-field signature.

Confidence is `min(struct confidence values) - 0.05`, clamped to `0.60..0.75`.

No scalar-only arrays are inferred in Phase 6C.

## Typed references

Every existing normalized `ReferenceRecord` receives exactly one parallel `TypedReferenceRecord` with the same source/target identity and original `kind`.

If its target address matches the start of an inferred `DataTypeRecord`, attach that type and confidence. Otherwise use `target_type="unknown"`, confidence `0.00`, and empty evidence.

This preserves all original references and avoids changing Phase 2 serialization.

## Function-pointer call enrichment

Phase 6C must not invent calls merely because a function address appears in data.

A new `TypedCallEdge` is emitted only when an existing `ReferenceRecord(kind="indirect_call")` targets a data slot that Phase 6C has internally classified as a `function_pointer`, and the slot's stored value resolves to an exact discovered function start.

The edge kind is `typed_indirect` and its evidence must include both the existing indirect-call record and the function-pointer classification. The edge's `target_address` is the resolved function address, not the storage-slot address.

Direct calls and already-resolved Phase 6A indirect calls remain owned by `advanced.py`; Phase 6C call edges are additive metadata and are deduplicated against an identical existing Phase 6A indirect edge during project reporting.

## Conflict and overlap rules

Type precedence at the same start address is:

1. `string`
2. `jump_table`
3. `function_pointer_table`
4. `pointer_table`
5. `array_candidate`
6. `struct_candidate`
7. `function_pointer`
8. `pointer`

Composite types outrank their first leaf field because a struct/array commonly begins with a pointer field.

Higher-precedence types suppress lower-precedence records that begin at the same address.

Accepted strings, jump tables, and pointer tables reserve their complete byte ranges. Standalone leaf records and structured candidates whose storage addresses fall inside those ranges are suppressed from top-level output.

When two same-precedence candidates conflict, choose higher confidence; ties resolve deterministically by `(type_name, size, evidence)` lexical ordering and emit a warning.

## Project integration

`build_project_artifacts` runs Phase 6C after Phase 6A and optional Phase 6B NID resolution so generated-symbol precedence can honor strong NID names.

`generate_project` writes:

- `metadata/data_typing.json` — complete `DataTypingResult`;
- `metadata/data_types.json` — inferred data types only;
- `metadata/typed_references.json` — references annotated with inferred target type;
- `metadata/typed_callgraph.json` — Phase 6C typed-indirect edges after deduplication against identical Phase 6A indirect edges.

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
7. 3-entry pointer table with required corroboration -> accepted;
8. 3 mapped-looking values with no table corroboration -> rejected;
9. 2-entry table without relocation on both slots -> rejected;
10. 2-entry relocation-backed table -> accepted;
11. homogeneous function targets -> `function_pointer_table`;
12. section-boundary truncation stops table safely;
13. accepted table suppresses top-level child pointer records;
14. `struct_candidate` requires at least two accepted typed fields;
15. repeated field signatures -> `array_candidate`;
16. array/struct composite at an anchor outranks its first leaf pointer;
17. stronger string/jump-table/table typing suppresses overlapping weaker candidates;
18. typed references preserve all original reference identities one-for-one;
19. typed-indirect call edge requires an existing `indirect_call` plus function-pointer slot;
20. project generation emits all four Phase 6C metadata files;
21. strong type-generated symbols do not overwrite curated/NID/string/function names;
22. unmappable relocation produces a warning but no pointer evidence;
23. package exports API and reports version `0.8.0`;
24. complete Phase 1-6B regression suite remains green.

## Explicit non-goals

Phase 6C does not:

- decode/apply `PT_PRXRELOC2`;
- guess segment-relative semantics for currently stored Type-A relocations;
- recover exact C struct names, field names, enums, unions, or scalar signedness;
- infer scalar-only arrays;
- mutate Phase 2 symbols/functions/references;
- treat every mapped-looking word as a pointer;
- create speculative call-graph edges from data tables alone;
- extract ISO/CSO files or game assets.

Those remain later phases.
