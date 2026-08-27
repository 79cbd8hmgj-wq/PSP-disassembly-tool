# Phase 7G — Evidence-backed whole-game module placement

Phase 7G extends the explicit single-module relocated views from Phase 7F into the whole-game `game-project` workflow. It chooses one address per successfully parsed decrypted module, records how strong that choice is, and keeps a strict distinction between addresses supported as PSP runtime behavior and addresses invented only to make multi-module static analysis deterministic.

Phase 7G does **not** claim that every executable found on a PSP disc is resident at the same time.

## Placement classes

Every accepted module receives a `ModulePlacement` with one of three placement classes.

### `fixed`

An ELF with `e_type == ET_EXEC` keeps the virtual addresses already encoded in its `PT_LOAD` program headers.

- `placement_kind`: `fixed`
- `placement_confidence`: `1.0`
- `runtime_address_claim`: `true`
- `requires_relocation`: `false`

No Phase 7F relocation pass is needed because the image is already linked to fixed addresses.

### `boot_inferred`

A relocatable selected boot module uses the PSP low-allocation boot path. PSP user memory begins at `0x08800000`; the initial `0x4000` bytes are reserved by the user-memory allocator, so the first normal low allocation begins at `0x08804000`. The module's `PT_LOAD` alignment is then honored.

- `placement_kind`: `boot_inferred`
- `placement_confidence`: `0.95`
- `runtime_address_claim`: `true`
- `requires_relocation`: `true`

For ordinary 16-byte-aligned PRX images this produces `0x08804000`. A stricter valid power-of-two `PT_LOAD` alignment can move the selected base upward.

The boot placement is not displaced merely because some separately loadable fixed-address module declares an overlapping range. Disc presence does not prove simultaneous residency.

### `analysis`

A secondary relocatable PRX does not contain enough static evidence to recover its exact runtime address. PSP module loading can depend on dynamic load order, allocation direction/options, explicit caller parameters, unloading, and other runtime state that is not encoded by the disc inventory.

Phase 7G therefore gives each such PRX a deterministic, aligned, non-overlapping **analysis address**.

- `placement_kind`: `analysis`
- `placement_confidence`: `0.50`
- `runtime_address_claim`: `false`
- `requires_relocation`: `true`

These addresses are safe to use as a stable namespace for static analysis, Splat workspaces, reports, and game-wide linking. They must not be presented as observed runtime addresses.

Synthetic secondary placements avoid the ranges recorded for the inferred boot image, fixed `ET_EXEC` images, and earlier synthetic secondary placements. This avoids accidental cross-module address collisions in the combined analysis namespace even though real module lifetimes can overlap.

## Whole-game integration

`generate_game_project()` now performs module handling in two stages:

1. Parse every executable candidate, preserving the existing `needs_decryption` and per-module failure isolation behavior.
2. Plan placements for the usable decrypted modules, then run Phase 7F consistently wherever relocation is required.

For a relocatable module, the same planned `load_address` is passed to:

- `disassemble_file()` / spimdisasm;
- `generate_project()` / Splat;
- the relocated normalized model supplied to the game-wide Phase 6B linker.

This prevents function addresses, imports/exports, symbols, Splat VRAM, and cross-module NID data from silently mixing original PRX-relative addresses with relocated addresses.

Fixed `ET_EXEC` modules retain the existing non-relocated path.

## Placement metadata

Whole-game generation writes:

```text
metadata/module_placements.json
```

Each record contains:

- `path`
- `load_address`
- `original_image_base`
- `image_size`
- `image_end`
- `alignment`
- `placement_kind`
- `placement_confidence`
- `runtime_address_claim`
- `requires_relocation`
- `placement_evidence`

The corresponding placement fields are also copied into each successfully planned module record in `metadata/game_analysis.json`, including failed modules when the failure occurred after placement was known.

This makes the runtime-vs-analysis distinction explicit for downstream tooling instead of burying it in an address heuristic.

## Public API

The placement planner is available independently of disc orchestration:

```python
from pspdisasm import (
    ModulePlacement,
    ModulePlacementInput,
    plan_module_placements,
)

placements = plan_module_placements(
    [
        ModulePlacementInput(
            path="PSP_GAME/SYSDIR/EBOOT.BIN",
            is_boot=True,
            model=boot_model,
        ),
        ModulePlacementInput(
            path="PSP_GAME/USRDIR/MODULE.PRX",
            is_boot=False,
            model=module_model,
        ),
    ]
)
```

The planner requires a parsed ELF header and at least one non-empty `PT_LOAD` range per input. Invalid layouts fail closed instead of receiving guessed addresses.

## Safety and interpretation boundaries

Phase 7G does not:

- decrypt or decompress `~PSP` modules;
- infer a secondary module's true dynamic load order;
- infer caller-specified load addresses or high/low allocation options;
- assert that all fixed and inferred runtime ranges coexist;
- rewrite arbitrary constants because they resemble PSP addresses;
- replace Phase 7F relocation validation.

Malformed or unsupported secondary modules retain the game-project failure-isolation behavior. Encrypted modules remain `needs_decryption` and do not receive fabricated placements.

## Reference and licensing boundary

PPSSPP was used only as a behavioral reference for PSP user-memory layout, low-allocation behavior, ELF relocation decisions, and module-loading semantics. GPL implementation code is not copied into the MIT core.

The relevant behavioral facts used by Phase 7G are limited to externally observable loader semantics: PSP user memory begins at `0x08800000`, the initial `0x4000` user-memory region is reserved before normal low allocation, ELF `ET_EXEC` images retain fixed addresses, and relocatable modules can be assigned addresses by the loader depending on runtime allocation state/options.

Phase 7G implements its own bounded Python placement model and explicitly marks unsupported runtime inference as analysis-only.