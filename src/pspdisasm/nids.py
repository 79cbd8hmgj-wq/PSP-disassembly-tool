from __future__ import annotations

import csv
import json
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence

from .model import NidSymbol

_KIND_ALIASES = {
    "fun": "function",
    "func": "function",
    "function": "function",
    "var": "variable",
    "variable": "variable",
}


class NidDatabase:
    """Normalized library/kind/NID symbol database with deterministic precedence."""

    def __init__(self) -> None:
        self._symbols: dict[tuple[str, str, int], NidSymbol] = {}
        self.warnings: list[str] = []

    @staticmethod
    def normalize_kind(kind: str) -> str:
        normalized = str(kind).strip().lower()
        try:
            return _KIND_ALIASES[normalized]
        except KeyError as exc:
            raise ValueError(f"Unsupported NID kind: {kind!r}") from exc

    def add(self, symbol: NidSymbol) -> None:
        library = symbol.library.strip()
        kind = self.normalize_kind(symbol.kind)
        normalized = NidSymbol(
            library=library,
            nid=_parse_nid(symbol.nid),
            name=symbol.name.strip(),
            kind=kind,
            source=symbol.source.strip(),
        )
        if not normalized.library:
            raise ValueError("NID library name must not be empty")
        if not normalized.name:
            raise ValueError("NID symbol name must not be empty")
        key = (normalized.library, normalized.kind, normalized.nid)
        previous = self._symbols.get(key)
        if (
            previous is not None
            and previous.name != normalized.name
            and not is_placeholder_name(previous.library, previous.nid, previous.name)
            and not is_placeholder_name(normalized.library, normalized.nid, normalized.name)
        ):
            self.warnings.append(
                "Conflicting NID names for "
                f"{normalized.library}/{normalized.kind}/0x{normalized.nid:08X}: "
                f"{previous.name!r} ({previous.source}) -> {normalized.name!r} ({normalized.source}); "
                "later database wins"
            )
        self._symbols[key] = normalized

    def resolve(self, library: str, nid: int | str, kind: str) -> NidSymbol | None:
        key = (library.strip(), self.normalize_kind(kind), _parse_nid(nid))
        return self._symbols.get(key)

    def symbols(self) -> list[NidSymbol]:
        return sorted(
            self._symbols.values(),
            key=lambda item: (item.library, item.kind, item.nid, item.name, item.source),
        )


def _parse_nid(value: int | str) -> int:
    if isinstance(value, bool):
        raise ValueError("NID must be an integer or hexadecimal string")
    if isinstance(value, int):
        nid = value
    else:
        text = str(value).strip()
        if not text:
            raise ValueError("NID must not be empty")
        if text.lower().startswith("0x"):
            nid = int(text, 16)
        elif re.fullmatch(r"[0-9A-Fa-f]{8}", text):
            nid = int(text, 16)
        else:
            nid = int(text, 10)
    if not 0 <= nid <= 0xFFFFFFFF:
        raise ValueError(f"NID out of range: {nid}")
    return nid


def is_placeholder_name(library: str, nid: int | str, name: str) -> bool:
    expected = f"{library.strip()}_{_parse_nid(nid):08X}"
    return name.strip().casefold() == expected.casefold()


def _symbol_from_mapping(record: Mapping[str, object], source_default: str) -> NidSymbol:
    library = record.get("library", record.get("library_name", ""))
    kind = record.get("kind", record.get("fun/var", record.get("type", "")))
    nid = record.get("nid", record.get("NID", ""))
    name = record.get("name", "")
    source = record.get("source", source_default)
    return NidSymbol(
        library=str(library),
        nid=_parse_nid(nid),
        name=str(name),
        kind=NidDatabase.normalize_kind(str(kind)),
        source=str(source or source_default),
    )


def _load_json(path: Path) -> list[NidSymbol]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("symbols", payload.get("nids"))
    if not isinstance(payload, list):
        raise ValueError(f"NID JSON {path} must contain a list or an object with 'symbols'")
    records: list[NidSymbol] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"NID JSON {path} record {index} is not an object")
        records.append(_symbol_from_mapping(item, path.name))
    return records


def _looks_like_csv_header(row: Sequence[str]) -> bool:
    if not row:
        return False
    first = row[0].strip().lower()
    third = row[2].strip().lower() if len(row) > 2 else ""
    return "library" in first or third == "nid"


def _load_csv(path: Path) -> list[NidSymbol]:
    records: list[NidSymbol] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row_number, row in enumerate(reader, start=1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if row[0].lstrip().startswith("#"):
                continue
            if row_number == 1 and _looks_like_csv_header(row):
                continue
            if len(row) < 4:
                raise ValueError(f"NID CSV {path} row {row_number} needs at least 4 columns")
            source = row[4].strip() if len(row) >= 5 and row[4].strip() else path.name
            records.append(
                NidSymbol(
                    library=row[0].strip(),
                    kind=NidDatabase.normalize_kind(row[1]),
                    nid=_parse_nid(row[2]),
                    name=row[3].strip(),
                    source=source,
                )
            )
    return records


def load_nid_databases(paths: Iterable[Path | str]) -> NidDatabase:
    database = NidDatabase()
    for raw_path in paths:
        path = Path(raw_path)
        suffix = path.suffix.lower()
        if suffix == ".json":
            records = _load_json(path)
        elif suffix in {".csv", ".txt"}:
            records = _load_csv(path)
        else:
            raise ValueError(f"Unsupported NID database format for {path}; expected .json or .csv")
        for symbol in records:
            database.add(symbol)
    return database
