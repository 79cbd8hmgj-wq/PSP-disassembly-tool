# Phase 7D review checklist

- Unknown extensions remain hints only; no universal proprietary archive claims.
- Built-in proprietary parser registry remains empty without real format evidence.
- Parser acceptance requires confidence >= 0.90.
- Parser probe/inspect failures remain resource-local warnings.
- Container entry paths and byte ranges are validated before extraction.
- Total accepted extracted bytes per container cannot exceed the parent file size.
- Traversal/symlink containment violations remain fatal.
- Extracted entries preserve parent path, parser, inner path, offset, and size provenance.
- Known entry formats reuse the shared Phase 6D/7C detector layer.
- Candidate, family, inspection, and entry outputs are deterministic.
- Full legacy suite remains green before merge.
