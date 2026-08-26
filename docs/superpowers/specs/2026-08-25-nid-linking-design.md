# Phase 6B NID Resolution and Cross-Module Linking Design

## Goal

Add a PSP-aware symbol-intelligence layer that can resolve import/export NIDs to names, connect imports to exports across multiple modules, and propagate trustworthy symbol names without coupling the core package to one third-party NID database.

## External data compatibility

The primary compatibility target is PSPDev PSPLibDoc's tabular model: library name, function/variable kind, NID, symbol name, and provenance/source. The core package will not vendor PSPLibDoc data. Instead it will load user-supplied databases and preserve source/provenance on every resolved name.

The first implementation supports:

- a simple JSON record format owned by pspdisasm;
- PSPLibDoc-style CSV rows/headers;
- multiple databases merged in command order, with deterministic precedence.

XML and direct PPSSPP-source parsing are deferred because CSV/JSON already provide a stable normalized boundary.

## Core records

Add normalized records:

- `NidSymbol(library, nid, name, kind, source)`
- `NidResolution(module, library, nid, name, kind, address, direction, source)`
- `ModuleLink(importing_module, exporting_module, library, nid, name, kind, import_address, export_address, name_source)`
- `PropagatedSymbol(module, address, name, kind, library, nid, source, confidence)`
- `ModuleLinkAnalysis(modules, resolutions, links, propagated_symbols, warnings)`

Kinds are `function` or `variable`. Directions are `import` or `export`.

## NID database rules

Lookup identity is exactly `(library, kind, nid)`.

- Library matching is exact after surrounding whitespace is stripped; case is preserved.
- NIDs accept integers, `0x` hexadecimal strings, or bare 8-digit hexadecimal strings.
- Kind aliases `fun`, `func`, `function`, `var`, and `variable` are normalized.
- Unknown/placeholder names following `<library>_<8HEX>` are retained as database facts but are not considered strong names for propagation.
- When multiple loaded records share an identity, the later database wins. A warning records conflicting non-placeholder names.

## Resolution rules

For every import/export `NidEntry` in an `ExecutableModel`:

1. Look up `(library, kind, nid)` in the loaded database.
2. If found, emit a `NidResolution` retaining database provenance.
3. If not found, use deterministic fallback name `<library>_<NID>` with source `unresolved`.

Resolution never mutates the parsed executable model.

## Cross-module link rules

Given multiple executable models:

- index exports by `(library, kind, nid)`;
- link an import only when exactly one export candidate exists in a different supplied module;
- if zero candidates exist, leave it unresolved as a cross-module relationship;
- if multiple export candidates exist, emit an ambiguity warning and no link;
- prefer a strong database name when available;
- otherwise propagate a strong resolved export name when available;
- otherwise retain the deterministic fallback `<library>_<NID>`.

This deliberately avoids guessing between multiple possible providers.

## Symbol propagation rules

Produce symbol suggestions rather than mutating low-level function records.

- A strong database-resolved export/import name receives confidence `1.0`.
- A name propagated through a unique exact import/export link receives confidence `0.95`.
- Placeholder/unresolved names receive confidence `0.50` and are emitted for traceability but should not replace curated names.
- Function import stubs and function exports produce `kind="function"` proposals; variables produce `kind="variable"` proposals.
- Duplicate proposals at the same `(module, address)` are resolved by higher confidence, then deterministic lexical ordering.

## Project integration

Single-module project generation gains optional NID databases. When provided it writes:

- `metadata/nids.json` — all import/export resolutions;
- `metadata/propagated_symbols.json` — name suggestions for this module.

Strong propagated names are also added to generated `config/symbols.txt` when they do not collide with the ELF entry point, a string symbol, or an already named discovered function.

## Multi-module CLI

Add:

```text
pspdisasm link module1.prx module2.prx [...] --nid-db FILE [--nid-db FILE ...] --json PATH
```

The command analyzes supplied decrypted ELF/PRX inputs, builds cross-module links, and emits the normalized `ModuleLinkAnalysis` JSON. NID databases are optional; exact import/export linking still works without them.

## Testing

Use synthetic `ExecutableModel` objects and existing PRX fixtures. Cover:

- PSPLibDoc-style CSV parsing;
- JSON parsing and precedence;
- exact library/kind/NID lookup;
- placeholder handling;
- unique cross-module links;
- ambiguity handling;
- strong-name and link-name propagation;
- project metadata/symbol integration;
- CLI multi-module link output;
- complete Phase 1–6A regression suite.
