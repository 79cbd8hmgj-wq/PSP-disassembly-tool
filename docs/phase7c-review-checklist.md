# Phase 7C pre-merge review checklist

Reviewed against `docs/superpowers/specs/2026-08-26-game-resource-orchestration-design.md`.

- Shared Phase 6D/7C format detectors remain bounded and conservative.
- PNG/JPEG/RIFF/VAG declared extents are checked against available data before extraction.
- GIM/PMF may remain metadata-only when a trustworthy full extent is unavailable.
- Loose files are classified by content, not extension.
- Unknown/proprietary files remain explicitly `unknown`.
- Disc resource extraction validates traversal/symlink containment before copying.
- Game-resource analysis validates extracted paths before resource-local failure isolation.
- Embedded extraction re-validates destination containment.
- Full embedded scans are capped at 64 MiB per loose file.
- Files above the ceiling remain inventoried and receive a deterministic warning.
- Resource-local read/extraction failures do not abort unrelated resources/modules.
- Integrity/containment failures remain fatal.
- `pspdisasm game` remains the Phase 7A scan-only command.
- `game-project` performs Phase 7A + 7B + 7C.
- No universal proprietary archive parser is claimed or shipped.
- The container parser registry is intentionally empty pending evidence from real game formats.
- PPSSPP remains reference-only; GPL implementation code is not copied into the MIT core.
- No commercial game data or uploaded upstream source archives are committed.
