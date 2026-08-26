# Phase 7D — Proprietary container intelligence

Phase 7D extends the Phase 7C unknown-resource boundary with deterministic container fingerprinting, family grouping, and a safe parser extension interface. It deliberately does **not** claim that common game-data extensions identify universal PSP archive formats.

The built-in proprietary parser set remains empty until a real target game provides enough structural evidence to implement and test a format safely.

## Whole-game behavior

`pspdisasm game-project` continues to perform the complete whole-game pipeline. After Phase 7C classifies loose resources, every file that remains `unknown` becomes a Phase 7D container candidate.

Without any custom parser, Phase 7D still produces useful reverse-engineering intelligence:

- normalized suffix hint;
- file size;
- first 16 bytes as exact hexadecimal;
- printable ASCII view of those bytes;
- Shannon entropy over at most the first 64 KiB;
- existing embedded-resource count;
- total byte size of bounded embedded resources already discovered;
- deterministic family grouping by suffix plus the first four content bytes.

These fields are descriptive evidence only. They do not change an unknown file into a claimed archive format.

## Candidate families

The default family key is:

```text
<lowercase-suffix>:<first-four-bytes-hex>
```

For example, two unknown `.DAT` files beginning with `PACK` receive:

```text
.dat:5041434b
```

This is intentionally a clustering aid rather than a format identifier. It helps an analyst locate repeated container structures across a game while preserving uncertainty.

## Parser API

Programmatic callers may supply evidence-backed parsers:

```python
from pathlib import Path

from pspdisasm import (
    ContainerEntry,
    ContainerInspection,
    ResourceContainerParser,
    generate_game_project,
)


class GameArchiveParser:
    name = "my-game-archive"

    def probe(self, prefix: bytes, path: str) -> float:
        if prefix.startswith(b"PACK"):
            return 0.99
        return 0.0

    def inspect(self, path: Path) -> ContainerInspection:
        return ContainerInspection(
            parser_name=self.name,
            format_name="game_pack",
            confidence=0.99,
            entries=[
                ContainerEntry(
                    path="textures/icon.png",
                    offset=0x100,
                    size=0x2000,
                )
            ],
        )


result = generate_game_project(
    "game.iso",
    "game_decomp",
    container_parsers=[GameArchiveParser()],
)
```

The CLI does not dynamically import arbitrary parser modules in Phase 7D. That keeps command-line execution from becoming a code-loading boundary while the Python API remains extensible for trusted tooling.

## Parser selection

For each unknown file, the orchestrator calls every supplied parser's `probe(prefix, logical_path)` method with the same bounded prefix.

Selection rules are deterministic:

1. probe exceptions are recorded as warnings;
2. non-finite values and values outside `[0.0, 1.0]` are rejected;
3. confidence below `0.90` is ignored;
4. the highest accepted confidence wins;
5. equal confidence is resolved by parser name and then original parser order.

A selected parser is still not trusted to control filesystem paths or byte ranges directly.

## Entry validation and extraction

A parser may return `ContainerEntry` values containing an inner path, byte offset, byte size, and optional metadata.

Before extraction, Phase 7D enforces:

- non-empty relative POSIX inner path;
- no absolute path;
- no `..` path component;
- containment beneath the project container-output root, including symlink resolution;
- offset greater than or equal to zero;
- size greater than zero;
- `offset + size <= parent file size`;
- at most 4096 accepted parser entries per parent container.

Unsafe paths are fatal game-project integrity errors. Invalid byte ranges are parser-local warnings and are never silently truncated.

Valid entries are copied exactly beneath:

```text
resources/containers/<parent-logical-disc-path>/<entry-logical-path>
```

Extraction streams bounded ranges instead of requiring the complete parent container to be loaded into memory.

## Extracted-entry classification

After extraction, an entry is passed through the same neutral content detector layer used by Phases 6D and 7C.

That means an archive entry can immediately be recognized as one of the currently supported resource formats:

- PNG;
- JPEG;
- RIFF/WAVE;
- ATRAC-family AT3;
- VAG;
- GIM;
- PSMF/PMF.

Unsupported entry contents remain `unknown`. Phase 7D does not guess based on the inner filename extension.

## Provenance

Every accepted entry records:

- parent logical disc path;
- selected parser name;
- inner logical path;
- parent-file byte offset;
- byte size;
- extracted relative path;
- detected resource format/kind/confidence;
- detector evidence;
- parser and detector metadata.

This preserves the chain from the original PSP disc file to an extracted resource without losing the range from which it came.

## Output layout

Phase 7D adds:

```text
game_decomp/
├── metadata/
│   ├── game_resources.json
│   ├── embedded_resources.json
│   ├── container_candidates.json
│   └── container_inspections.json
├── reports/
│   ├── game_resources.csv
│   ├── container_candidates.csv
│   └── container_entries.csv
└── resources/
    ├── files/
    │   └── PSP_GAME/...
    ├── embedded/
    │   └── PSP_GAME/...
    └── containers/
        └── PSP_GAME/.../<container>/<inner-path>
```

`metadata/game_resources.json` contains the complete normalized `GameResourceAnalysis`, including candidate families and extracted entry records. The standalone candidate and inspection files make those two common analyst workflows easier to consume directly.

## Error boundaries

Fatal integrity failures include:

- unsafe loose-resource paths;
- unsafe parser-provided inner paths;
- symlink escapes;
- failures that prevent deterministic project/report creation.

Resource/parser-local failures remain non-fatal where containment is intact:

- parser probe exception;
- invalid probe confidence;
- parser inspection exception;
- out-of-bounds byte range;
- too many returned entries;
- isolated bounded-entry extraction failure;
- unknown extracted resource format.

The failure is retained as a warning and analysis continues with other files.

## Determinism

Normalized output contains no timestamps or environment-dependent absolute host paths.

Records are ordered by stable logical identifiers:

- resources and candidates by logical disc path;
- families by family key, with member paths sorted;
- inspections by parent path and parser name;
- entries by parent path, parser name, byte offset, and inner path.

## Deliberate limitations

Phase 7D does not yet:

- ship a speculative universal parser for `.BIN`, `.DAT`, `.ARC`, `.PAC`, `.PAK`, or `.PKG`;
- recursively unpack nested proprietary containers;
- infer anonymous entry names or semantic asset roles;
- decompress unknown game-specific codecs;
- decrypt encrypted `~PSP` executables;
- transcode textures, models, audio, or video.

The next format-specific parser should be driven by an actual unknown container from a target PSP game, with its structure established from repeated evidence before implementation.
