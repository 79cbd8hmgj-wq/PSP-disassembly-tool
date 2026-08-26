# Phase 7A — PSP ISO/CSO Disc Intake

Phase 7A adds a whole-disc entry point in front of the existing executable-analysis pipeline. It inventories a PSP game image, reads PSP metadata, chooses the boot executable, discovers additional executable/module candidates, and extracts those candidates into a deterministic workspace for the next analysis phase.

## Install disc support

```bash
python -m pip install -e '.[analysis,disc]'
```

The `disc` extra installs `pycdlib` for ISO9660 traversal and `lz4` for CISO v2 LZ4 blocks. Existing executable-only commands do not require either dependency.

## Scan a game image

```bash
pspdisasm game GAME.iso game_intake
```

Compressed images use the same command:

```bash
pspdisasm game GAME.cso game_intake
```

The scanner supports raw ISO9660 images, CISO v0/v1 raw-DEFLATE blocks, and CISO v2 DEFLATE/LZ4 blocks. It reads CSO data block-by-block and does not expand the whole image to a temporary ISO.

## Output

```text
game_intake/
├── metadata/
│   ├── disc.json
│   └── param_sfo.json
└── modules/
    └── PSP_GAME/
        ├── SYSDIR/
        │   └── EBOOT.BIN
        └── USRDIR/
            └── ... discovered PRX/executable candidates
```

`metadata/disc.json` is the Phase 7B handoff. It records:

- image format;
- title and disc identity from `PARAM.SFO` when present;
- selected boot path;
- every ISO file with size and classification;
- discovered executable/module candidates;
- extracted module paths;
- deterministic warnings.

ISO9660 version suffixes such as `;1` are removed from logical manifest paths.

## Boot selection

The scanner follows the standard PSP disc layout:

1. Prefer `PSP_GAME/SYSDIR/EBOOT.BIN` when it begins with ELF or `~PSP` magic.
2. Otherwise use `PSP_GAME/SYSDIR/BOOT.BIN` when it begins with ELF or `~PSP` magic.
3. Reject the image if neither path contains a usable executable candidate.

Additional `.PRX` files and files beginning with ELF or `~PSP` magic are recorded as module candidates.

## Encryption boundary

Phase 7A can inventory and extract encrypted `~PSP` containers, but it does not bypass PSP executable encryption. Existing executable analysis continues to stop safely at that boundary. Phase 7B will analyze decrypted ELF/PRX candidates automatically and record encrypted candidates as explicit unresolved inputs until a lawful decryption backend is supplied.

## Source and license boundary

The implementation was designed from three external references without merging their codebases into this MIT project:

- PPSSPP is used as a behavioral reference for PSP disc layout and boot conventions; its GPL implementation is not copied.
- maxcso's ISC-licensed CISO format behavior informs the small Python block reader.
- pycdlib remains an optional LGPL runtime dependency; its source is not copied into `pspdisasm`.

## Deferred to Phase 7B+

Phase 7A intentionally does not perform game-wide disassembly or unified project generation. Later phases will consume the manifest to add:

- per-module executable analysis and Allegrex disassembly;
- automatic NID/cross-module linking;
- unified game-level metadata and decompilation workspaces;
- recursive game-wide asset analysis;
- additional compressed/container formats such as ZSO/DAX where justified.
