from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
from importlib import metadata as importlib_metadata
import json
from pathlib import Path, PurePosixPath
import posixpath
import shutil
from typing import BinaryIO, Iterable

from .disc import GameDiscManifest, scan_game_disc
from .disc_image import open_disc_stream
from .errors import EngineUnavailableError, ParseError, WorkspaceError
from .game_project import GameProjectResult, generate_game_project


WORKSPACE_SCHEMA_VERSION = 1
ANALYSIS_SCHEMA_VERSION = 1
_HASH_CHUNK_BYTES = 1024 * 1024
_LOCAL_FILE = ".pspdisasm-local.json"
_FILES_MANIFEST = "manifests/files.json"
_WORKSPACE_FILE = "workspace.json"
_ANALYSIS_STATE = "analysis/state.json"


@dataclass(frozen=True, slots=True)
class WorkspaceFileRecord:
    path: str
    size: int
    sha256: str
    source_kind: str
    classification: str
    executable_kind: str = "unknown"
    analysis_state: str = "pending"
    analysis_version: int = ANALYSIS_SCHEMA_VERSION


@dataclass(slots=True)
class GameWorkspaceManifest:
    schema_version: int
    toolkit_version: str
    source_kind: str
    source_name: str
    source_identity: str
    files: list[WorkspaceFileRecord]


@dataclass(slots=True)
class WorkspaceAnalysisResult:
    workspace_dir: Path
    analysis_dir: Path
    analysis_key: str
    reused: bool
    game_project: GameProjectResult


def _toolkit_version() -> str:
    try:
        return importlib_metadata.version("pspdisasm")
    except importlib_metadata.PackageNotFoundError:
        return "0.9.0"


def _sha256_stream(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(_HASH_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_path(path: Path) -> str:
    with path.open("rb") as handle:
        return _sha256_stream(handle)


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    try:
        temp.write_text(text, encoding="utf-8")
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def _safe_logical_path(value: str) -> str:
    pure = PurePosixPath(value.replace("\\", "/"))
    if not value or pure.is_absolute() or ".." in pure.parts:
        raise WorkspaceError(f"Unsafe workspace logical path: {value}")
    normalized = "/".join(part for part in pure.parts if part not in ("", "."))
    if not normalized:
        raise WorkspaceError(f"Unsafe workspace logical path: {value}")
    return normalized


def _executable_kind(prefix: bytes) -> str:
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"~PSP"):
        return "psp_container"
    return "unknown"


def _directory_classification(path: str, executable_kind: str) -> str:
    folded = path.casefold()
    if folded in {
        "psp_game/sysdir/eboot.bin",
        "psp_game/sysdir/boot.bin",
    }:
        return "boot"
    if folded == "umd_data.bin" or folded.endswith("/param.sfo") or folded in {
        "psp_game/icon0.png",
        "psp_game/pic0.png",
        "psp_game/pic1.png",
    }:
        return "metadata"
    if folded.endswith(".prx") or executable_kind != "unknown":
        return "module"
    return "resource"


def _directory_entries(root: Path) -> tuple[list[WorkspaceFileRecord], list[dict[str, object]]]:
    if not root.is_dir():
        raise WorkspaceError(f"Extracted PSP source is not a directory: {root}")
    records: list[WorkspaceFileRecord] = []
    snapshot: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_symlink():
            raise WorkspaceError(f"Symlinks are not allowed in extracted PSP sources: {path}")
        if not path.is_file():
            continue
        logical = _safe_logical_path(path.relative_to(root).as_posix())
        stat = path.stat()
        with path.open("rb") as handle:
            prefix = handle.read(4)
            handle.seek(0)
            sha256 = _sha256_stream(handle)
        kind = _executable_kind(prefix)
        records.append(
            WorkspaceFileRecord(
                path=logical,
                size=stat.st_size,
                sha256=sha256,
                source_kind="directory",
                classification=_directory_classification(logical, kind),
                executable_kind=kind,
            )
        )
        snapshot.append({"path": logical, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
    records.sort(key=lambda item: item.path.casefold())
    snapshot.sort(key=lambda item: str(item["path"]).casefold())
    if not records:
        raise WorkspaceError("Extracted PSP source contains no files")
    return records, snapshot


def _iso_logical_path(physical_path: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(physical_path).parts:
        if part in ("/", ""):
            continue
        if ";" in part:
            name, suffix = part.rsplit(";", 1)
            if suffix.isdigit():
                part = name
        parts.append(part)
    return _safe_logical_path("/".join(parts))


def _load_pycdlib():
    try:
        import pycdlib
    except ImportError as exc:
        raise EngineUnavailableError(
            "PSP workspace preparation requires pycdlib; install pspdisasm with the 'disc' extra"
        ) from exc
    return pycdlib


def _disc_entries(source: Path) -> tuple[list[WorkspaceFileRecord], dict[str, object], GameDiscManifest]:
    manifest = scan_game_disc(source)
    metadata_by_path = {record.path.casefold(): record for record in manifest.files}
    pycdlib = _load_pycdlib()
    iso = pycdlib.PyCdlib()
    records: list[WorkspaceFileRecord] = []
    try:
        with open_disc_stream(source) as (_image_format, stream):
            iso.open_fp(stream)
            physical: list[tuple[str, str]] = []
            for directory, _dirs, names in iso.walk(iso_path="/", encoding="utf-8"):
                for name in names:
                    physical_path = posixpath.join(directory, name)
                    if not physical_path.startswith("/"):
                        physical_path = "/" + physical_path
                    physical.append((_iso_logical_path(physical_path), physical_path))
            for logical, physical_path in sorted(physical, key=lambda item: item[0].casefold()):
                source_record = metadata_by_path.get(logical.casefold())
                if source_record is None:
                    raise WorkspaceError(f"Disc manifest lost source file during hashing: {logical}")
                with iso.open_file_from_iso(iso_path=physical_path) as handle:
                    sha256 = _sha256_stream(handle)
                records.append(
                    WorkspaceFileRecord(
                        path=logical,
                        size=source_record.size,
                        sha256=sha256,
                        source_kind=manifest.image_format,
                        classification=source_record.classification,
                        executable_kind=source_record.executable_kind,
                    )
                )
    except (EngineUnavailableError, ParseError, WorkspaceError):
        raise
    except Exception as exc:
        raise WorkspaceError(f"Unable to hash PSP disc members: {exc}") from exc
    finally:
        try:
            iso.close()
        except Exception:
            pass

    stat = source.stat()
    snapshot = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    return records, snapshot, manifest


def _source_identity(records: Iterable[WorkspaceFileRecord]) -> str:
    identity = [
        {
            "path": record.path,
            "size": record.size,
            "sha256": record.sha256,
            "source_kind": record.source_kind,
            "classification": record.classification,
            "executable_kind": record.executable_kind,
        }
        for record in sorted(records, key=lambda item: item.path.casefold())
    ]
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _portable_workspace(manifest: GameWorkspaceManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "toolkit_version": manifest.toolkit_version,
        "source_kind": manifest.source_kind,
        "source_name": manifest.source_name,
        "source_identity": manifest.source_identity,
        "files_manifest": _FILES_MANIFEST,
    }


def _write_workspace(manifest: GameWorkspaceManifest, workspace: Path, source: Path, snapshot: object) -> None:
    files_payload = [asdict(record) for record in manifest.files]
    _atomic_write_text(workspace / _WORKSPACE_FILE, _json_text(_portable_workspace(manifest)))
    _atomic_write_text(workspace / _FILES_MANIFEST, _json_text(files_payload))
    local_payload = {
        "schema_version": WORKSPACE_SCHEMA_VERSION,
        "source_kind": manifest.source_kind,
        "source_path": str(source.resolve()),
        "snapshot": snapshot,
    }
    _atomic_write_text(workspace / _LOCAL_FILE, _json_text(local_payload))


def prepare_game_workspace(
    source: Path | str,
    workspace_dir: Path | str,
) -> GameWorkspaceManifest:
    source_path = Path(source)
    workspace = Path(workspace_dir)
    if not source_path.exists():
        raise WorkspaceError(f"PSP workspace source does not exist: {source_path}")
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "analysis").mkdir(exist_ok=True)
    (workspace / "packs").mkdir(exist_ok=True)
    (workspace / "cache").mkdir(exist_ok=True)

    if source_path.is_dir():
        records, snapshot = _directory_entries(source_path)
        source_kind = "directory"
    elif source_path.is_file():
        records, snapshot, disc_manifest = _disc_entries(source_path)
        source_kind = disc_manifest.image_format
    else:
        raise WorkspaceError(f"Unsupported PSP workspace source: {source_path}")

    manifest = GameWorkspaceManifest(
        schema_version=WORKSPACE_SCHEMA_VERSION,
        toolkit_version=_toolkit_version(),
        source_kind=source_kind,
        source_name=source_path.name,
        source_identity=_source_identity(records),
        files=records,
    )
    _write_workspace(manifest, workspace, source_path, snapshot)
    return manifest


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkspaceError(f"Workspace metadata is missing: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"Workspace metadata is invalid: {path.name}: {exc}") from exc


def load_game_workspace(workspace_dir: Path | str) -> GameWorkspaceManifest:
    workspace = Path(workspace_dir)
    portable = _load_json(workspace / _WORKSPACE_FILE)
    files = _load_json(workspace / _FILES_MANIFEST)
    if not isinstance(portable, dict) or not isinstance(files, list):
        raise WorkspaceError("Workspace metadata has an invalid schema")
    schema = portable.get("schema_version")
    if schema != WORKSPACE_SCHEMA_VERSION:
        raise WorkspaceError(
            f"Unsupported workspace schema version {schema!r}; expected {WORKSPACE_SCHEMA_VERSION}"
        )
    try:
        records = [WorkspaceFileRecord(**record) for record in files if isinstance(record, dict)]
        manifest = GameWorkspaceManifest(
            schema_version=WORKSPACE_SCHEMA_VERSION,
            toolkit_version=str(portable["toolkit_version"]),
            source_kind=str(portable["source_kind"]),
            source_name=str(portable["source_name"]),
            source_identity=str(portable["source_identity"]),
            files=records,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkspaceError(f"Workspace metadata has an invalid schema: {exc}") from exc
    if len(records) != len(files):
        raise WorkspaceError("Workspace file manifest contains invalid records")
    if _source_identity(records) != manifest.source_identity:
        raise WorkspaceError("Workspace file manifest does not match its source identity")
    return manifest


def _load_local_source(workspace: Path, manifest: GameWorkspaceManifest) -> tuple[Path, object]:
    local = _load_json(workspace / _LOCAL_FILE)
    if not isinstance(local, dict) or local.get("schema_version") != WORKSPACE_SCHEMA_VERSION:
        raise WorkspaceError("Workspace local source metadata has an invalid schema")
    if local.get("source_kind") != manifest.source_kind:
        raise WorkspaceError("Workspace local source kind does not match portable metadata")
    source_value = local.get("source_path")
    if not isinstance(source_value, str) or not source_value:
        raise WorkspaceError("Workspace local source path is missing")
    source = Path(source_value)
    if not source.exists():
        raise WorkspaceError(f"Workspace source is no longer available: {source}")
    return source, local.get("snapshot")


def _validate_snapshot(source: Path, source_kind: str, snapshot: object) -> None:
    if source_kind == "directory":
        if not isinstance(snapshot, list):
            raise WorkspaceError("Workspace local directory snapshot is invalid")
        current: list[dict[str, object]] = []
        for path in sorted(source.rglob("*"), key=lambda item: item.as_posix().casefold()):
            if path.is_symlink():
                raise WorkspaceError(f"Symlinks are not allowed in extracted PSP sources: {path}")
            if not path.is_file():
                continue
            logical = _safe_logical_path(path.relative_to(source).as_posix())
            stat = path.stat()
            current.append({"path": logical, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
        if current != snapshot:
            raise WorkspaceError("Workspace source changed; run prepare-game again before analysis")
        return

    if not isinstance(snapshot, dict):
        raise WorkspaceError("Workspace local disc snapshot is invalid")
    stat = source.stat()
    current = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    if current != snapshot:
        raise WorkspaceError("Workspace source changed; run prepare-game again before analysis")


def _analysis_key(manifest: GameWorkspaceManifest, nid_databases: Iterable[Path | str]) -> str:
    nid_identity: list[dict[str, object]] = []
    for value in nid_databases:
        path = Path(value)
        if not path.is_file():
            raise WorkspaceError(f"NID database is not readable: {path}")
        nid_identity.append({"size": path.stat().st_size, "sha256": _sha256_path(path)})
    payload = {
        "source_identity": manifest.source_identity,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "toolkit_version": _toolkit_version(),
        "nid_databases": nid_identity,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _state_to_game_project(analysis_root: Path, payload: dict[str, object]) -> GameProjectResult:
    summary = payload.get("game_project")
    if not isinstance(summary, dict):
        raise WorkspaceError("Workspace analysis state is missing game-project summary data")

    def number(name: str) -> int:
        value = summary.get(name)
        if not isinstance(value, int):
            raise WorkspaceError(f"Workspace analysis state has invalid {name}")
        return value

    game_root = analysis_root / "game_project"
    return GameProjectResult(
        output_dir=game_root,
        analysis_path=game_root / "metadata/game_analysis.json",
        links_path=game_root / "metadata/module_links.json",
        module_count=number("module_count"),
        analyzed_count=number("analyzed_count"),
        needs_decryption_count=number("needs_decryption_count"),
        failed_count=number("failed_count"),
        resource_count=number("resource_count"),
        known_resource_count=number("known_resource_count"),
        unknown_resource_count=number("unknown_resource_count"),
        embedded_resource_count=number("embedded_resource_count"),
        container_candidate_count=number("container_candidate_count"),
        container_inspection_count=number("container_inspection_count"),
        container_entry_count=number("container_entry_count"),
        resources_path=game_root / "metadata/game_resources.json",
        containers_path=game_root / "metadata/container_candidates.json",
        placements_path=game_root / "metadata/module_placements.json",
    )


def _game_project_summary(result: GameProjectResult) -> dict[str, int]:
    return {
        "module_count": result.module_count,
        "analyzed_count": result.analyzed_count,
        "needs_decryption_count": result.needs_decryption_count,
        "failed_count": result.failed_count,
        "resource_count": result.resource_count,
        "known_resource_count": result.known_resource_count,
        "unknown_resource_count": result.unknown_resource_count,
        "embedded_resource_count": result.embedded_resource_count,
        "container_candidate_count": result.container_candidate_count,
        "container_inspection_count": result.container_inspection_count,
        "container_entry_count": result.container_entry_count,
    }


def _update_analysis_states(workspace: Path, manifest: GameWorkspaceManifest, result: GameProjectResult) -> None:
    states: dict[str, str] = {}
    try:
        analysis = json.loads(result.analysis_path.read_text(encoding="utf-8"))
        for record in analysis.get("modules", []):
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                states[record["path"].casefold()] = str(record.get("status", "analyzed"))
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    if result.resources_path is not None and result.resources_path.exists():
        try:
            resources = json.loads(result.resources_path.read_text(encoding="utf-8"))
            for record in resources.get("resources", []):
                if isinstance(record, dict) and isinstance(record.get("path"), str):
                    states[record["path"].casefold()] = "analyzed"
        except (OSError, json.JSONDecodeError, AttributeError):
            pass

    updated = [
        replace(record, analysis_state=states.get(record.path.casefold(), record.analysis_state))
        for record in manifest.files
    ]
    manifest.files = updated
    _atomic_write_text(workspace / _FILES_MANIFEST, _json_text([asdict(record) for record in updated]))


def analyze_game_workspace(
    workspace_dir: Path | str,
    *,
    nid_databases: Iterable[Path | str] = (),
) -> WorkspaceAnalysisResult:
    workspace = Path(workspace_dir)
    manifest = load_game_workspace(workspace)
    source, snapshot = _load_local_source(workspace, manifest)
    _validate_snapshot(source, manifest.source_kind, snapshot)
    databases = tuple(nid_databases)
    analysis_key = _analysis_key(manifest, databases)
    analysis_root = workspace / "analysis"
    game_root = analysis_root / "game_project"
    state_path = workspace / _ANALYSIS_STATE

    if state_path.exists() and (game_root / "metadata/game_analysis.json").is_file():
        state = _load_json(state_path)
        if isinstance(state, dict) and state.get("analysis_key") == analysis_key:
            game_project = _state_to_game_project(analysis_root, state)
            return WorkspaceAnalysisResult(
                workspace_dir=workspace,
                analysis_dir=analysis_root,
                analysis_key=analysis_key,
                reused=True,
                game_project=game_project,
            )

    if game_root.exists():
        shutil.rmtree(game_root)
    game_project = generate_game_project(source, game_root, nid_databases=databases)
    _update_analysis_states(workspace, manifest, game_project)
    state = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_key": analysis_key,
        "source_identity": manifest.source_identity,
        "game_project": _game_project_summary(game_project),
    }
    _atomic_write_text(state_path, _json_text(state))
    return WorkspaceAnalysisResult(
        workspace_dir=workspace,
        analysis_dir=analysis_root,
        analysis_key=analysis_key,
        reused=False,
        game_project=game_project,
    )
