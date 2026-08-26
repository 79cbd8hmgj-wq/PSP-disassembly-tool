from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path, PurePosixPath
import posixpath
from typing import BinaryIO

from .disc_image import open_disc_stream
from .errors import EngineUnavailableError, ParseError
from .sfo import parse_param_sfo


_ELF_MAGIC = b"\x7fELF"
_PSP_MAGIC = b"~PSP"
_PARAM_SFO = "PSP_GAME/PARAM.SFO"
_UMD_DATA = "UMD_DATA.BIN"
_EBOOT = "PSP_GAME/SYSDIR/EBOOT.BIN"
_BOOT = "PSP_GAME/SYSDIR/BOOT.BIN"
_METADATA_NAMES = {_PARAM_SFO, _UMD_DATA, "PSP_GAME/ICON0.PNG", "PSP_GAME/PIC0.PNG", "PSP_GAME/PIC1.PNG"}


@dataclass(slots=True)
class DiscFileRecord:
    path: str
    size: int
    classification: str
    executable_kind: str = "unknown"


@dataclass(slots=True)
class GameModuleRecord:
    path: str
    size: int
    executable_kind: str
    output_path: str | None = None
    is_boot: bool = False


@dataclass(slots=True)
class DiscResourceRecord:
    path: str
    size: int
    output_path: str


@dataclass(slots=True)
class GameDiscManifest:
    source_name: str
    image_format: str
    title: str | None = None
    disc_id: str | None = None
    disc_version: str | None = None
    psp_system_version: str | None = None
    boot_path: str | None = None
    files: list[DiscFileRecord] = field(default_factory=list)
    modules: list[GameModuleRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _IsoFile:
    physical_path: str
    logical_path: str
    size: int
    magic: bytes


def _load_pycdlib():
    try:
        import pycdlib
    except ImportError as exc:
        raise EngineUnavailableError(
            "PSP disc scanning requires pycdlib; install pspdisasm with the 'disc' extra"
        ) from exc
    return pycdlib


def _logical_path(physical_path: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(physical_path).parts:
        if part in ("/", ""):
            continue
        if ";" in part:
            name, suffix = part.rsplit(";", 1)
            if suffix.isdigit():
                part = name
        parts.append(part)
    return "/".join(parts)


def _executable_kind(magic: bytes) -> str:
    if magic.startswith(_ELF_MAGIC):
        return "elf"
    if magic.startswith(_PSP_MAGIC):
        return "psp_container"
    return "unknown"


def _read_prefix(iso, physical_path: str, size: int = 4) -> bytes:
    with iso.open_file_from_iso(iso_path=physical_path) as fp:
        return fp.read(size)


def _read_file(iso, physical_path: str) -> bytes:
    with iso.open_file_from_iso(iso_path=physical_path) as fp:
        return fp.read()


def _walk_files(iso) -> list[_IsoFile]:
    files: list[_IsoFile] = []
    for directory, _dirs, names in iso.walk(iso_path="/", encoding="utf-8"):
        for name in names:
            physical = posixpath.join(directory, name)
            if not physical.startswith("/"):
                physical = "/" + physical
            record = iso.get_record(iso_path=physical)
            size = int(record.data_length)
            files.append(
                _IsoFile(
                    physical_path=physical,
                    logical_path=_logical_path(physical),
                    size=size,
                    magic=_read_prefix(iso, physical),
                )
            )
    return sorted(files, key=lambda item: item.logical_path.casefold())


def _choose_boot(files: list[_IsoFile]) -> str | None:
    by_path = {item.logical_path.casefold(): item for item in files}
    for candidate in (_EBOOT, _BOOT):
        item = by_path.get(candidate.casefold())
        if item is not None and _executable_kind(item.magic) != "unknown":
            return item.logical_path
    return None


def _classification(item: _IsoFile, boot_path: str) -> str:
    logical = item.logical_path
    if logical.casefold() == boot_path.casefold():
        return "boot"
    if logical in _METADATA_NAMES or logical.endswith("/PARAM.SFO"):
        return "metadata"
    if logical.upper().endswith(".PRX") or _executable_kind(item.magic) != "unknown":
        return "module"
    return "resource"


def _json_safe_sfo(values: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in sorted(values, key=str.casefold):
        value = values[key]
        if isinstance(value, bytes):
            result[key] = {"raw_hex": value.hex()}
        else:
            result[key] = value
    return result


def _safe_target(root: Path, logical_path: str) -> Path:
    pure = PurePosixPath(logical_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ParseError(f"Unsafe disc extraction path: {logical_path}")
    root = root.resolve()
    target = (root / Path(*pure.parts)).resolve()
    if target != root and root not in target.parents:
        raise ParseError(f"Unsafe disc extraction path: {logical_path}")
    return target


def _copy_iso_file(iso, physical_path: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with iso.open_file_from_iso(iso_path=physical_path) as source, destination.open("wb") as output:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)


def _write_metadata(output_dir: Path, manifest: GameDiscManifest, sfo: dict[str, object]) -> None:
    metadata = output_dir / "metadata"
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / "disc.json").write_text(
        json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (metadata / "param_sfo.json").write_text(
        json.dumps(_json_safe_sfo(sfo), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def scan_game_disc(path: Path | str, output_dir: Path | str | None = None) -> GameDiscManifest:
    source = Path(path)
    pycdlib = _load_pycdlib()
    iso = pycdlib.PyCdlib()
    try:
        with open_disc_stream(source) as (image_format, stream):
            try:
                iso.open_fp(stream)
                iso_files = _walk_files(iso)
                boot_path = _choose_boot(iso_files)
                if boot_path is None:
                    raise ParseError("PSP disc contains no usable EBOOT.BIN or BOOT.BIN executable")

                physical_by_logical = {item.logical_path: item.physical_path for item in iso_files}
                sfo: dict[str, object] = {}
                sfo_physical = physical_by_logical.get(_PARAM_SFO)
                warnings: list[str] = []
                if sfo_physical is not None:
                    try:
                        sfo = parse_param_sfo(_read_file(iso, sfo_physical))
                    except ParseError as exc:
                        warnings.append(f"PARAM.SFO could not be parsed: {exc}")
                else:
                    warnings.append("PSP_GAME/PARAM.SFO is missing")

                file_records: list[DiscFileRecord] = []
                module_records: list[GameModuleRecord] = []
                output_root = Path(output_dir) if output_dir is not None else None
                modules_root = output_root / "modules" if output_root is not None else None

                for item in iso_files:
                    classification = _classification(item, boot_path)
                    kind = _executable_kind(item.magic)
                    file_records.append(
                        DiscFileRecord(
                            path=item.logical_path,
                            size=item.size,
                            classification=classification,
                            executable_kind=kind,
                        )
                    )
                    if classification not in ("boot", "module"):
                        continue

                    output_path: str | None = None
                    if modules_root is not None:
                        target = _safe_target(modules_root, item.logical_path)
                        _copy_iso_file(iso, item.physical_path, target)
                        output_path = str(target.relative_to(output_root.resolve()))
                    module_records.append(
                        GameModuleRecord(
                            path=item.logical_path,
                            size=item.size,
                            executable_kind=kind,
                            output_path=output_path,
                            is_boot=classification == "boot",
                        )
                    )

                file_records.sort(key=lambda item: item.path.casefold())
                module_records.sort(key=lambda item: item.path.casefold())
                manifest = GameDiscManifest(
                    source_name=str(source),
                    image_format=image_format.value,
                    title=_string_value(sfo.get("TITLE")),
                    disc_id=_string_value(sfo.get("DISC_ID")),
                    disc_version=_string_value(sfo.get("DISC_VERSION")),
                    psp_system_version=_string_value(sfo.get("PSP_SYSTEM_VER")),
                    boot_path=boot_path,
                    files=file_records,
                    modules=module_records,
                    warnings=warnings,
                )
                if output_root is not None:
                    _write_metadata(output_root, manifest, sfo)
                return manifest
            except (ParseError, EngineUnavailableError):
                raise
            except Exception as exc:
                raise ParseError(f"Unable to read PSP ISO9660 filesystem: {exc}") from exc
            finally:
                try:
                    iso.close()
                except Exception:
                    pass
    except (ParseError, EngineUnavailableError):
        raise


def extract_disc_resources(
    path: Path | str,
    output_dir: Path | str,
    *,
    manifest: GameDiscManifest | None = None,
) -> list[DiscResourceRecord]:
    source = Path(path)
    output_root = Path(output_dir)
    selected_manifest = manifest if manifest is not None else scan_game_disc(source)
    resource_files = sorted(
        [record for record in selected_manifest.files if record.classification == "resource"],
        key=lambda item: item.path.casefold(),
    )
    resources_root = output_root / "resources" / "files"

    targets: dict[str, Path] = {}
    for record in resource_files:
        targets[record.path] = _safe_target(resources_root, record.path)

    if not resource_files:
        return []

    pycdlib = _load_pycdlib()
    iso = pycdlib.PyCdlib()
    try:
        with open_disc_stream(source) as (_image_format, stream):
            try:
                iso.open_fp(stream)
                physical_by_logical = {
                    item.logical_path: item.physical_path
                    for item in _walk_files(iso)
                }
                results: list[DiscResourceRecord] = []
                for record in resource_files:
                    physical_path = physical_by_logical.get(record.path)
                    if physical_path is None:
                        raise ParseError(f"Disc resource is missing from image: {record.path}")
                    target = targets[record.path]
                    _copy_iso_file(iso, physical_path, target)
                    results.append(
                        DiscResourceRecord(
                            path=record.path,
                            size=record.size,
                            output_path=str(target.relative_to(output_root.resolve())),
                        )
                    )
                return results
            except (ParseError, EngineUnavailableError):
                raise
            except Exception as exc:
                raise ParseError(f"Unable to extract PSP disc resources: {exc}") from exc
            finally:
                try:
                    iso.close()
                except Exception:
                    pass
    except (ParseError, EngineUnavailableError):
        raise


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) else None
