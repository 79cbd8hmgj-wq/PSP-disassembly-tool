# Phase 7E — PSP PT_PRXRELOC2 decoding

Phase 7E adds bounded clean-room decoding for PSP `PT_PRXRELOC2` compressed relocation streams, integrates decoded Type-B relocations into normal PRX analysis, and exposes an explicit pure relocation-word application primitive.

The phase deliberately does **not** choose a runtime load address or silently mutate bytes before disassembly. Existing Type-A relocations remain metadata-only in that path as well, so any future relocated load view must treat both relocation families consistently behind an explicit caller-selected load address.

## Decoder

`decode_prxreloc2(data, elf, relocation_segment_index)` validates and decodes one bounded `PT_PRXRELOC2` program-header segment.

Supported state/base encodings:

- `0x00` — compact base encoded in the command word;
- `0x04` — absolute little-endian `u32` base following the command.

Supported relocation-offset encodings:

- `0x00` — compact signed delta;
- `0x02` — signed extended delta using the command high part plus a following `u16` low part;
- `0x04` — absolute little-endian `u32` source offset.

The PSP compact relocation type table is normalized as:

| Compact type | Normalized relocation |
| ---: | --- |
| 0 | `R_MIPS_NONE` |
| 1 | `R_MIPS_16` |
| 2 | `R_MIPS_32` |
| 3 | `R_MIPS_26` |
| 4 | `R_MIPS_HI16` |
| 5 | `R_MIPS_LO16` |
| 6 | `R_MIPS_X_J26` |
| 7 | `R_MIPS_X_JAL26` |

Each decoded relocation retains additive provenance on the normalized `Relocation` model:

- source `PT_LOAD` segment index;
- target `PT_LOAD` segment index;
- compressed-stream command offset;
- resolved or unresolved addend state;
- raw encoding flags.

## HI16 low-half state

The compressed stream can carry additional state needed by `R_MIPS_HI16`.

- `0x00` is represented with `addend=0`.
- `0x10` consumes a following signed `u16` and preserves it as the explicit addend.
- `0x08` is an ambiguous reuse/state mode. Phase 7E deliberately preserves it as `addend=None` rather than guessing a low half from emulator-specific mutable state.

An unresolved HI16 relocation can still be applied later if the caller supplies an explicit `lo16=` value.

## Explicit relocation application

`apply_psp_relocation_word(word, relocation, target_base, *, lo16=None)` is a pure 32-bit word transform. The caller must provide `target_base`; the function never chooses a PSP runtime address and never mutates an ELF image on its own.

The helper supports the decoded PSP operations:

- `R_MIPS_NONE`;
- `R_MIPS_16`;
- `R_MIPS_32`;
- `R_MIPS_26`;
- `R_MIPS_HI16`;
- `R_MIPS_LO16`;
- `R_MIPS_X_J26`;
- `R_MIPS_X_JAL26`.

Unresolved HI16 state is rejected unless the caller provides `lo16=` explicitly.

## PRX-analysis integration

`analyze_prx()` now includes valid Type-B relocations alongside Type-A section/program-header relocations. A malformed `PT_PRXRELOC2` segment does not discard otherwise usable PRX metadata or Type-A relocations; its failure is isolated as a deterministic warning identifying the program-header index.

The normalized model therefore exposes Type-B relocation metadata automatically through existing `analyze_bytes()` / `analyze_file()` workflows.

## Safety boundaries

The decoder rejects malformed input rather than reading speculatively. Coverage includes:

- truncated headers, lookup tables, commands, extended deltas, absolute offsets, and HI16 addends;
- command bit-width overflow;
- flag/type lookup-table index overflow;
- source or target references that are not `PT_LOAD` segments;
- relocation words that would extend beyond the source segment's `memsz`;
- a hard decoded-relocation-count ceiling.

Phase 7E does not add PSP cryptographic decryption, `~PSP` body decompression, automatic runtime rebasing, or silent pre-disassembly relocation application.

## Public API

```python
from pspdisasm import apply_psp_relocation_word, decode_prxreloc2
```

## Reference boundary

The compressed-stream and relocation behavior was checked against the supplied PPSSPP source as a behavioral reference. PPSSPP is GPL-licensed; no PPSSPP implementation code is copied into the MIT toolkit core. The ambiguous `0x08` HI16 state is intentionally represented conservatively rather than reproducing emulator-specific mutable state.

The detailed design is in `docs/superpowers/specs/2026-08-26-prxreloc2-design.md`.
