# Phase 7E — PSP PT_PRXRELOC2 decoding

Phase 7E adds bounded decoding for PSP `PT_PRXRELOC2` compressed relocation streams and pure relocation-word application primitives.

The phase deliberately does **not** choose a runtime load address or silently mutate bytes before disassembly. Existing Type-A relocations are also metadata-only today, so automatic rebasing must be introduced later as one explicit load-view layer that treats both relocation families consistently.

The detailed design is in `docs/superpowers/specs/2026-08-26-prxreloc2-design.md`.
