# Phase 6B NID Resolution and Cross-Module Linking Plan

**Goal:** Resolve PSP import/export NIDs, connect exact cross-module dependencies, and propagate trustworthy names into analysis/project outputs.

**Architecture:** Keep NID data loading pure-Python and external-data-driven. Build resolution/linking on `ExecutableModel` records, then integrate optional strong names into project generation and expose multi-module linking through a CLI command.

## Task 1 — NID database model and loaders

**Files:**
- Modify: `src/pspdisasm/model.py`
- Create: `src/pspdisasm/nids.py`
- Create: `tests/test_nids.py`

- [ ] Write failing tests for JSON and PSPLibDoc-style CSV loading.
- [ ] Verify RED state.
- [ ] Implement normalization, lookup, placeholders, precedence, conflict warnings.
- [ ] Verify focused tests green.

## Task 2 — Module resolution, exact linking, and propagation

**Files:**
- Create: `src/pspdisasm/linker.py`
- Modify: `src/pspdisasm/model.py`
- Create: `tests/test_linker.py`

- [ ] Write failing tests for unique links, ambiguous providers, unresolved fallbacks, and symbol proposals.
- [ ] Verify RED state.
- [ ] Implement resolution and multi-module linker.
- [ ] Verify focused tests green.

## Task 3 — Single-module project integration

**Files:**
- Modify: `src/pspdisasm/project.py`
- Modify: `tests/test_project.py`

- [ ] Add failing tests for optional NID metadata and symbols.txt propagation.
- [ ] Verify RED state.
- [ ] Add optional `nid_databases` input to project generation.
- [ ] Emit `metadata/nids.json` and `metadata/propagated_symbols.json` when databases are supplied.
- [ ] Add only strong, non-colliding propagated names to generated symbols.
- [ ] Verify project tests green.

## Task 4 — CLI and public API

**Files:**
- Modify: `src/pspdisasm/cli.py`
- Modify: `src/pspdisasm/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`
- Modify/Create CLI tests as appropriate.

- [ ] Add repeatable `--nid-db` to `project`.
- [ ] Add `link` command accepting multiple decrypted ELF/PRX inputs and optional databases.
- [ ] Export NID/linker APIs.
- [ ] Bump version to `0.7.0`.
- [ ] Document database format and Phase 6B artifacts.
- [ ] Run complete suite and verify no Phase 1–6A regressions.
