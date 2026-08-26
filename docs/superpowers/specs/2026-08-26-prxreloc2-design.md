# Phase 7E — PT_PRXRELOC2 Decoding Design

## Status

Approved continuation after merged Phase 7D. Phase 7E closes the remaining PSP executable-analysis gap where compressed `PT_PRXRELOC2` relocation streams are detected but not decoded.

## Goals

Phase 7E must:

- decode structurally valid PSP `PT_PRXRELOC2` program-header streams into the existing normalized `Relocation` model;
- preserve the source segment, target segment, compressed-stream position, raw encoding flags, and any explicit HI16 low-half addend needed to understand or later apply a relocation;
- map the compact Type-B relocation codes onto the existing PSP/MIPS relocation identifiers where semantics are known;
- isolate malformed compressed streams as PRX-analysis warnings rather than crashing whole-game analysis;
- expose a pure relocation-word application primitive that requires an explicit target segment base and never invents a runtime load address;
- leave existing Type-A `SHT_PRXRELOC` / `PT_PRXRELOC` behavior compatible;
- remain deterministic and bounded on hostile or malformed inputs.

## Non-goals

Phase 7E does not:

- decrypt encrypted `~PSP` bodies;
- choose a synthetic PSP runtime load address;
- silently rewrite bytes before spimdisasm/Splat analysis;
- build a complete relocated in-memory PRX image;
- claim semantics for unsupported compact relocation types;
- guess the meaning of ambiguous compressed-stream state when source evidence is insufficient;
- change proprietary game-resource/container behavior from Phase 7D.

A later load-view phase may use the normalized Type-A and Type-B relocation records to construct an explicitly rebased analysis image.

## Source and licensing boundary

The compressed-stream behavior is implemented clean-room from behavioral/reference evidence:

- the supplied PPSSPP source documents the PSP loader's `PT_PRXRELOC2` bitstream structure, table-driven command decoding, source/target segment state, delta/absolute offset modes, and supported relocation operations;
- PSPDev/prxtool definitions corroborate `PT_PRXRELOC2 = 0x700000A1` and PSP custom relocation identifiers `R_MIPS_X_HI16` (13), `R_MIPS_X_J26` (14), and `R_MIPS_X_JAL26` (15);
- the supplied spimdisasm source provides the MIT-side conventional MIPS relocation vocabulary but does not implement PSP `PT_PRXRELOC2` decoding.

No GPL PPSSPP implementation code is copied into the MIT core.

## Existing behavior

`src/pspdisasm/prx.py` currently:

- parses standard/PSP Type-A relocation entries as 8-byte `Elf32_Rel` records;
- detects `PT_PRXRELOC2` program headers;
- emits only a warning that compressed relocation decoding is not implemented.

`disassembler.py` parses the original ELF and passes its raw bytes to spimdisasm. Existing Type-A relocations are metadata only; therefore Phase 7E must not apply Type-B relocations behind the caller's back.

## Architecture

### 1. Dedicated compressed-relocation module

Create `src/pspdisasm/prxreloc2.py` so the byte-level decoder and application rules are isolated from module/import/export parsing in `prx.py`.

Public/internal interfaces:

```python
def decode_prxreloc2(
    data: bytes,
    elf: ElfImage,
    relocation_segment_index: int,
) -> list[Relocation]: ...


def apply_psp_relocation_word(
    word: int,
    relocation: Relocation,
    target_base: int,
    *,
    lo16: int | None = None,
) -> int: ...
```

`decode_prxreloc2` raises `ParseError` for malformed/unsupported compressed streams. `prx.py` catches that at the individual relocation-segment boundary, records a deterministic warning, and continues other PRX analysis.

`apply_psp_relocation_word` is a pure 32-bit operation. It never reads process memory, chooses segment addresses, or mutates an ELF.

### 2. Additive relocation provenance

Extend `Relocation` with defaulted fields so existing callers remain source-compatible:

```python
source_segment_index: int | None = None
target_segment_index: int | None = None
stream_offset: int | None = None
addend: int | None = None
encoding_flags: int | None = None
```

For Type-B records:

- `offset` is the decoded byte offset within the source `PT_LOAD` segment;
- `info` is a normalized PSP-style synthetic value containing type, source-segment index, and target-segment index;
- `source_segment_index` and `target_segment_index` retain those identities explicitly;
- `stream_offset` is the byte offset within the `PT_PRXRELOC2` stream at which the command began;
- `addend` stores a resolved signed HI16 low-half value when present;
- `encoding_flags` stores the selected flag-table byte.

Existing Type-A records retain their prior core fields. Where their program-header form already encodes source/target segments, the new explicit fields may also be populated without changing existing `info` or `symbol_index` values.

### 3. Stream header and table decoding

A Type-B relocation program header is accepted only when:

- the program-header index exists and is `PT_PRXRELOC2`;
- `p_offset + p_filesz` is fully inside the input;
- at least four bytes are present for the compressed header;
- the ELF is little-endian;
- the derived bit widths fit inside a 16-bit command word.

The compressed header uses:

- byte 2: `flag_bits`;
- byte 3: `type_bits`.

`seg_bits` is the smallest positive bit width able to represent preceding program-header indices, matching PSP loader behavior for the relocation segment's program-header index.

The flag and type lookup tables follow the four-byte header. Each begins with a byte that declares the complete table byte length, including the size byte itself. Table lengths and every later table index are bounds-checked.

### 4. Command decoding

Commands are little-endian 16-bit words and may consume additional bytes.

The low command fields select:

1. a flag-table index;
2. a segment index;
3. for relocation commands, a type-table index.

Flag bit 0 distinguishes state/base commands from emitted relocation commands.

#### State/base command

A state command updates the current source/offset segment and relocation base.

Supported offset modes (`flag & 0x06`):

- `0x00`: compact base encoded in the command;
- `0x04`: absolute little-endian 32-bit base following the command.

Other state-command offset modes are rejected.

#### Relocation command

A relocation command names the target segment and updates/sets the current source-segment offset.

Supported offset modes:

- `0x00`: signed compact delta encoded in the command;
- `0x02`: signed extended delta using an additional little-endian 16-bit low half;
- `0x04`: absolute little-endian 32-bit offset following the command.

The decoded source and target segment indices must identify `PT_LOAD` program headers before a relocation record is emitted.

The resulting source offset must fit within the source segment's memory span sufficiently to address a 32-bit relocation word. File-backed byte application is deliberately not performed here.

### 5. Compact type mapping

Known Type-B compact relocation operations normalize as:

| Compact type | Normalized PSP/MIPS type |
| ---: | ---: |
| 0 | `R_MIPS_NONE` (0) |
| 1 | `R_MIPS_16` (1) |
| 2 | `R_MIPS_32` (2) |
| 3 | `R_MIPS_26` (4) |
| 4 | `R_MIPS_HI16` (5) |
| 5 | `R_MIPS_LO16` (6) |
| 6 | `R_MIPS_X_J26` (14) |
| 7 | `R_MIPS_X_JAL26` (15) |

A type-table value outside the supported compact set fails the affected compressed segment with a warning rather than being mislabeled as a standard MIPS relocation.

### 6. HI16 low-half modes

`flag & 0x38` controls the low-half context used by a compressed HI16 relocation:

- `0x00`: resolved low half is zero;
- `0x10`: an explicit signed 16-bit low half follows the command;
- `0x08`: reuse/continuation state is indicated by the format, but available independent evidence does not establish a safe normalized addend rule.

For `0x08`, the decoder preserves the flag and records `addend=None`. Decoding succeeds, but the pure application primitive refuses to apply an HI16 relocation whose required low-half value remains unresolved. This is intentionally safer than guessing from one emulator implementation detail.

Other low-half modes are rejected.

### 7. Pure application primitive

`apply_psp_relocation_word` takes an explicit target segment runtime base supplied by the caller and performs only the relocation's 32-bit word transformation.

Supported normalized operations:

- `R_MIPS_NONE`: unchanged;
- `R_MIPS_16` / `R_MIPS_LO16`: add target base to the low 16 bits;
- `R_MIPS_32`: add target base to the full 32-bit word;
- `R_MIPS_26`: add target-base/4 to the 26-bit jump field;
- `R_MIPS_HI16`: use a supplied/resolved signed low half and MIPS carry adjustment;
- `R_MIPS_X_J26`: apply jump relocation and force opcode `j`;
- `R_MIPS_X_JAL26`: apply jump relocation and force opcode `jal`.

All arithmetic is explicitly masked to 32 bits where PSP/MIPS word behavior requires wrapping.

Unsupported relocation types raise `ParseError` rather than silently producing a guessed word.

### 8. Analyzer integration

`prx._parse_relocations()` will call `decode_prxreloc2()` for each Type-B relocation segment.

On success:

- decoded entries are appended in deterministic stream order;
- the old "decoding is not implemented" warning disappears.

On malformed/unsupported input:

- the decoder's `ParseError` becomes one PRX warning identifying the program-header index;
- other relocation sections/segments and module metadata remain available.

### 9. Determinism and safety ceilings

The decoder:

- never reads beyond `p_filesz`;
- checks every extension read before consuming it;
- checks every table index;
- checks all bit-width shifts;
- validates source/target segment identity;
- uses a decoded-record ceiling derived from stream size with an explicit hard maximum;
- rejects arithmetic/offset states that cannot address a 32-bit word inside the declared source segment memory span;
- emits no timestamps or environment-dependent data.

## Testing

Synthetic tests must cover:

1. minimal valid state command plus `R_MIPS_32` relocation;
2. compact positive and negative deltas;
3. extended signed delta mode;
4. absolute 32-bit offset mode;
5. compact type mapping for 0–7;
6. explicit signed HI16 low-half addend;
7. unresolved `0x08` HI16 reuse state is preserved and not guessed during application;
8. forced `j` / `jal` custom relocation application;
9. truncated header, flag table, type table, command, u16 extension, and u32 extension;
10. invalid flag/type table indices and invalid bit widths;
11. non-`PT_LOAD` source/target segment indices;
12. source offset outside segment memory bounds;
13. analyzer integration removes the old not-implemented warning for a valid stream;
14. malformed Type-B stream remains a warning while existing Type-A relocations still parse;
15. all legacy tests remain green.

## Success criteria

Phase 7E is complete when valid synthetic `PT_PRXRELOC2` streams produce deterministic normalized relocation records with full segment/stream provenance, malformed streams fail closed at the segment boundary, pure relocation-word operations are tested without inventing runtime addresses, and the complete existing suite remains green.