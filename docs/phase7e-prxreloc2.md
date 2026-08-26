# Phase 7E — PSP PT_PRXRELOC2 decoding

Phase 7E adds bounded decoding for PSP `PT_PRXRELOC2` compressed relocation streams and pure relocation-word application primitives.

The phase deliberately does **not** choose a runtime load address or silently mutate bytes before disassembly. Existing Type-A relocations are also metadata-only today, so automatic rebasing must be introduced later as one explicit load-view layer that treats both relocation families consistently.

## Implementation status

Work is proceeding test-first on `phase7e-prxreloc2` / draft PR #10.

The currently verified decoder surface is intentionally narrow:

- additive compressed-relocation provenance on the normalized `Relocation` model;
- bounded Type-B header and lookup-table parsing;
- compact state/base commands;
- compact signed relocation deltas;
- source/target `PT_LOAD` and 32-bit source-range validation;
- normalized `R_MIPS_32` output with stream/segment provenance.

Extended/absolute offset modes, the remaining compact relocation types, HI16 low-half state, malformed-stream matrix, pure word application, and `prx.py` integration are still subsequent TDD steps. The implementation does not claim those behaviors until their failing tests are added and made green.

The detailed design is in `docs/superpowers/specs/2026-08-26-prxreloc2-design.md`.
