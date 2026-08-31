from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Iterable
import zipfile

from .errors import AnalysisPackError
from .workspace import GameWorkspaceManifest, WorkspaceFileRecord, load_game_workspace


DEFAULT_PACK_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_CONTEXT_BYTES = 4096
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_HASH_CHUNK_BYTES = 1024 * 1024
_OPTIONAL_FULL_ARTIFACTS = {"evidence/module.bin", "evidence/resource.bin"}


@dataclass(slots=True)
class AnalysisPackResult:
    output_path: Path
    selector_kind: str
    selector_value: str
    artifact_count: int
    total_bytes: int
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _Artifact:
    path: str
    data: bytes


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _safe_logical_path(value: str, *, label: str = "selector") -> str:
    pure = PurePosixPath(value.replace("\\", "/"))
    if not value or pure.is_absolute() or ".." in pure.parts:
        raise AnalysisPackError(f"Unsafe {label} path: {value}")
    normalized = "/".join(part for part in pure.parts if part not in ("", "."))
    if not normalized:
        raise AnalysisPackError(f"Unsafe {label} path: {value}")
    return normalized


def _safe_child(root: Path, relative: str) -> Path:
    logical = _safe_logical_path(relative, label="analysis artifact")
    root_resolved = root.resolve()
    target = (root_resolved / Path(*PurePosixPath(logical).parts)).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise AnalysisPackError(f"Unsafe analysis artifact path: {relative}")
    return target


def _load_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AnalysisPackError(f"Required {label} is missing: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisPackError(f"Unable to read {label}: {exc}") from exc


def _portableize(value: object, *, logical_source: str, workspace_root: Path) -> object:
    """Remove machine-local paths from JSON evidence before it enters a pack."""
    if isinstance(value, list):
        return [
            _portableize(item, logical_source=logical_source, workspace_root=workspace_root)
            for item in value
        ]
    if isinstance(value, dict):
        output: dict[str, object] = {}
        for key, item in value.items():
            if key == "source_name" and isinstance(item, str):
                output[key] = logical_source
            else:
                output[key] = _portableize(
                    item,
                    logical_source=logical_source,
                    workspace_root=workspace_root,
                )
        return output
    if isinstance(value, str):
        root = str(workspace_root.resolve())
        return value.replace(root, "<workspace>") if root in value else value
    return value


def _find_file(manifest: GameWorkspaceManifest, logical_path: str) -> WorkspaceFileRecord:
    selected = _safe_logical_path(logical_path)
    matches = [record for record in manifest.files if record.path.casefold() == selected.casefold()]
    if len(matches) != 1:
        raise AnalysisPackError(f"Workspace source path was not found uniquely: {logical_path}")
    return matches[0]


def _analysis_root(workspace: Path) -> Path:
    root = workspace / "analysis/game_project"
    if not (root / "metadata/game_analysis.json").is_file():
        raise AnalysisPackError("Workspace has not been analyzed; run analyze-workspace first")
    return root


def _game_analysis(analysis_root: Path) -> dict[str, object]:
    payload = _load_json(analysis_root / "metadata/game_analysis.json", label="game analysis")
    if not isinstance(payload, dict) or not isinstance(payload.get("modules"), list):
        raise AnalysisPackError("Game analysis has an invalid module schema")
    return payload


def _module_record(analysis_root: Path, logical_path: str) -> dict[str, object]:
    selected = _safe_logical_path(logical_path)
    payload = _game_analysis(analysis_root)
    matches = [
        record
        for record in payload["modules"]
        if isinstance(record, dict)
        and isinstance(record.get("path"), str)
        and record["path"].casefold() == selected.casefold()
    ]
    if len(matches) != 1:
        raise AnalysisPackError(f"Analyzed module was not found uniquely: {logical_path}")
    return matches[0]


def _single_analyzed_module(analysis_root: Path) -> dict[str, object]:
    payload = _game_analysis(analysis_root)
    matches = [
        record
        for record in payload["modules"]
        if isinstance(record, dict)
        and record.get("status") == "analyzed"
        and isinstance(record.get("path"), str)
        and isinstance(record.get("project_path"), str)
    ]
    if len(matches) != 1:
        raise AnalysisPackError(
            "Function pack is ambiguous without --module; select an analyzed module explicitly"
        )
    return matches[0]


def _resource_record(analysis_root: Path, logical_path: str) -> dict[str, object]:
    selected = _safe_logical_path(logical_path)
    payload = _load_json(analysis_root / "metadata/game_resources.json", label="resource analysis")
    if not isinstance(payload, dict) or not isinstance(payload.get("resources"), list):
        raise AnalysisPackError("Resource analysis has an invalid schema")
    matches = [
        record
        for record in payload["resources"]
        if isinstance(record, dict)
        and isinstance(record.get("path"), str)
        and record["path"].casefold() == selected.casefold()
    ]
    if len(matches) != 1:
        raise AnalysisPackError(f"Analyzed resource was not found uniquely: {logical_path}")
    return matches[0]


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise AnalysisPackError(f"Unable to hash selected source bytes: {exc}") from exc
    return digest.hexdigest()


def _verify_source_file(record: WorkspaceFileRecord, path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AnalysisPackError(f"Unable to stat selected source bytes: {exc}") from exc
    if size != record.size or _sha256_path(path) != record.sha256:
        raise AnalysisPackError(f"Analysis bytes no longer match workspace provenance: {record.path}")


def _read_small_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AnalysisPackError(f"Unable to stat {label}: {exc}") from exc
    if size > max_bytes:
        raise AnalysisPackError(f"{label} exceeds the analysis-pack budget")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AnalysisPackError(f"Unable to read {label}: {exc}") from exc


def _read_slice(path: Path, offset: int, size: int, *, label: str) -> bytes:
    if offset < 0 or size < 0:
        raise AnalysisPackError(f"Invalid {label} byte range")
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(size)
    except OSError as exc:
        raise AnalysisPackError(f"Unable to read {label}: {exc}") from exc
    if len(data) != size:
        raise AnalysisPackError(f"Unable to read complete {label}")
    return data


def _artifact_bytes(artifacts: Iterable[_Artifact]) -> int:
    return sum(len(artifact.data) for artifact in artifacts)


def _append(artifacts: list[_Artifact], path: str, data: bytes, *, max_bytes: int) -> None:
    logical = _safe_logical_path(path, label="pack artifact")
    if any(existing.path == logical for existing in artifacts):
        raise AnalysisPackError(f"Duplicate analysis-pack artifact: {logical}")
    if _artifact_bytes(artifacts) + len(data) > max_bytes:
        raise AnalysisPackError(
            f"Analysis-pack artifact {logical} exceeds the configured {max_bytes} byte budget"
        )
    artifacts.append(_Artifact(logical, data))


def _append_json(
    artifacts: list[_Artifact],
    path: str,
    value: object,
    *,
    max_bytes: int,
) -> None:
    _append(artifacts, path, _canonical_json(value), max_bytes=max_bytes)


def _append_optional_full_file(
    artifacts: list[_Artifact],
    artifact_path: str,
    source_path: Path,
    *,
    max_bytes: int,
    label: str,
) -> None:
    try:
        size = source_path.stat().st_size
    except OSError as exc:
        raise AnalysisPackError(f"Unable to stat {label}: {exc}") from exc
    remaining = max_bytes - _artifact_bytes(artifacts)
    if size > remaining:
        return
    data = _read_small_file(source_path, max_bytes=remaining, label=label)
    _append(artifacts, artifact_path, data, max_bytes=max_bytes)


def _project_root(analysis_root: Path, module_record: dict[str, object]) -> Path:
    project_value = module_record.get("project_path")
    if not isinstance(project_value, str) or not project_value:
        raise AnalysisPackError("Selected module has no generated analysis project")
    project = _safe_child(analysis_root, project_value)
    if not project.is_dir():
        raise AnalysisPackError("Selected module project is missing")
    return project


def _module_bytes_path(analysis_root: Path, module_record: dict[str, object]) -> Path:
    extracted_value = module_record.get("extracted_path")
    if not isinstance(extracted_value, str) or not extracted_value:
        raise AnalysisPackError("Selected module has no extracted byte provenance")
    path = _safe_child(analysis_root, extracted_value)
    if not path.is_file():
        raise AnalysisPackError("Selected module bytes are missing")
    return path


def _module_artifacts(
    analysis_root: Path,
    workspace_root: Path,
    source_record: WorkspaceFileRecord,
    module: dict[str, object],
    *,
    max_bytes: int,
) -> list[_Artifact]:
    artifacts: list[_Artifact] = []
    _append_json(artifacts, "evidence/module.json", module, max_bytes=max_bytes)
    project = _project_root(analysis_root, module)
    metadata_names = (
        "executable.json",
        "disassembly.json",
        "advanced.json",
        "data_typing.json",
        "asset_discovery.json",
        "functions.json",
        "symbols.json",
        "references.json",
        "strings.json",
    )
    for name in metadata_names:
        path = project / "metadata" / name
        if not path.is_file():
            continue
        portable = _portableize(
            _load_json(path, label=f"module metadata {name}"),
            logical_source=source_record.path,
            workspace_root=workspace_root,
        )
        _append_json(artifacts, f"metadata/{name}", portable, max_bytes=max_bytes)

    module_path = _module_bytes_path(analysis_root, module)
    _verify_source_file(source_record, module_path)
    _append_optional_full_file(
        artifacts,
        "evidence/module.bin",
        module_path,
        max_bytes=max_bytes,
        label="selected module",
    )
    return artifacts


def _select_function(functions: object, selector: str) -> dict[str, object]:
    if not isinstance(functions, list):
        raise AnalysisPackError("Function metadata has an invalid schema")
    address: int | None = None
    try:
        address = int(selector, 0)
    except ValueError:
        pass
    matches = [
        record
        for record in functions
        if isinstance(record, dict)
        and (
            (isinstance(record.get("name"), str) and record["name"] == selector)
            or (address is not None and record.get("address") == address)
        )
    ]
    if len(matches) != 1:
        raise AnalysisPackError(f"Function was not found uniquely: {selector}")
    return matches[0]


def _function_context_range(
    project: Path,
    module_size: int,
    function: dict[str, object],
    context_bytes: int,
) -> tuple[int, int]:
    executable = _load_json(project / "metadata/executable.json", label="executable metadata")
    if not isinstance(executable, dict) or not isinstance(executable.get("sections"), list):
        raise AnalysisPackError("Executable metadata cannot map the selected function to file bytes")
    address = function.get("address")
    size = function.get("size")
    if not isinstance(address, int) or not isinstance(size, int) or size < 0:
        raise AnalysisPackError("Selected function has invalid address/size metadata")
    section = next(
        (
            item
            for item in executable["sections"]
            if isinstance(item, dict)
            and isinstance(item.get("addr"), int)
            and isinstance(item.get("offset"), int)
            and isinstance(item.get("size"), int)
            and item["addr"] <= address < item["addr"] + item["size"]
        ),
        None,
    )
    if section is None:
        raise AnalysisPackError("Selected function is not backed by a file section")
    offset = section["offset"] + (address - section["addr"])
    function_end = offset + size
    if offset < 0 or function_end > module_size:
        raise AnalysisPackError("Selected function byte range is outside the source module")
    start = max(0, offset - context_bytes)
    end = min(module_size, function_end + context_bytes)
    return start, end


def _function_artifacts(
    analysis_root: Path,
    source_record: WorkspaceFileRecord,
    module: dict[str, object],
    selector: str,
    *,
    max_bytes: int,
    context_bytes: int,
) -> tuple[list[_Artifact], dict[str, object]]:
    project = _project_root(analysis_root, module)
    functions = _load_json(project / "metadata/functions.json", label="function metadata")
    selected = _select_function(functions, selector)
    address = selected.get("address")
    size = selected.get("size")
    if not isinstance(address, int) or not isinstance(size, int):
        raise AnalysisPackError("Selected function has invalid address/size metadata")
    end = address + size

    artifacts: list[_Artifact] = []
    _append_json(artifacts, "evidence/function.json", selected, max_bytes=max_bytes)
    instructions = selected.get("instructions", [])
    if not isinstance(instructions, list):
        instructions = []
    _append_json(artifacts, "evidence/instructions.json", instructions, max_bytes=max_bytes)

    references = _load_json(project / "metadata/references.json", label="reference metadata")
    filtered_references = []
    if isinstance(references, list):
        filtered_references = [
            record
            for record in references
            if isinstance(record, dict)
            and (
                (isinstance(record.get("source_address"), int) and address <= record["source_address"] < end)
                or (isinstance(record.get("target_address"), int) and address <= record["target_address"] < end)
            )
        ]
    _append_json(artifacts, "evidence/references.json", filtered_references, max_bytes=max_bytes)

    callgraph_path = project / "metadata/callgraph.json"
    call_edges: list[object] = []
    if callgraph_path.is_file():
        callgraph = _load_json(callgraph_path, label="call graph")
        name = selected.get("name")
        if isinstance(callgraph, list):
            call_edges = [
                edge
                for edge in callgraph
                if isinstance(edge, dict)
                and (
                    edge.get("source_function") == name
                    or edge.get("target_function") == name
                    or (isinstance(edge.get("source_address"), int) and address <= edge["source_address"] < end)
                    or (isinstance(edge.get("target_address"), int) and address <= edge["target_address"] < end)
                )
            ]
    _append_json(artifacts, "evidence/callgraph.json", call_edges, max_bytes=max_bytes)

    module_path = _module_bytes_path(analysis_root, module)
    _verify_source_file(source_record, module_path)
    context_start, context_end = _function_context_range(
        project,
        source_record.size,
        selected,
        context_bytes,
    )
    context = _read_slice(
        module_path,
        context_start,
        context_end - context_start,
        label="function context",
    )
    _append(artifacts, "evidence/context.bin", context, max_bytes=max_bytes)
    _append_json(
        artifacts,
        "evidence/context.json",
        {
            "parent_path": source_record.path,
            "parent_sha256": source_record.sha256,
            "file_offset": context_start,
            "size": len(context),
        },
        max_bytes=max_bytes,
    )
    return artifacts, selected


def _resource_artifacts(
    analysis_root: Path,
    source_record: WorkspaceFileRecord,
    resource: dict[str, object],
    *,
    max_bytes: int,
    context_bytes: int,
) -> list[_Artifact]:
    artifacts: list[_Artifact] = []
    _append_json(artifacts, "evidence/resource.json", resource, max_bytes=max_bytes)
    extracted_value = resource.get("extracted_path")
    if not isinstance(extracted_value, str) or not extracted_value:
        raise AnalysisPackError("Selected resource has no extracted byte provenance")
    resource_path = _safe_child(analysis_root, extracted_value)
    if not resource_path.is_file():
        raise AnalysisPackError("Selected resource bytes are missing")
    _verify_source_file(source_record, resource_path)

    sample_size = min(context_bytes, source_record.size)
    sample = _read_slice(resource_path, 0, sample_size, label="resource sample")
    _append(artifacts, "evidence/resource-sample.bin", sample, max_bytes=max_bytes)
    _append_optional_full_file(
        artifacts,
        "evidence/resource.bin",
        resource_path,
        max_bytes=max_bytes,
        label="selected resource",
    )

    for filename, key in (
        ("embedded_resources.json", "embedded"),
        ("container_inspections.json", "containers"),
    ):
        path = analysis_root / "metadata" / filename
        if not path.is_file():
            continue
        payload = _load_json(path, label=filename)
        matches: list[object] = []
        if isinstance(payload, list):
            matches = [
                item
                for item in payload
                if isinstance(item, dict)
                and isinstance(item.get("parent_path"), str)
                and item["parent_path"].casefold() == source_record.path.casefold()
            ]
        _append_json(artifacts, f"evidence/{key}.json", matches, max_bytes=max_bytes)
    return artifacts


def _artifact_manifest(artifacts: Iterable[_Artifact]) -> list[dict[str, object]]:
    return [
        {
            "path": artifact.path,
            "size": len(artifact.data),
            "sha256": hashlib.sha256(artifact.data).hexdigest(),
        }
        for artifact in sorted(artifacts, key=lambda item: item.path)
    ]


def _pack_manifest(
    manifest: GameWorkspaceManifest,
    source_record: WorkspaceFileRecord,
    selector_kind: str,
    selector_value: str,
    artifacts: list[_Artifact],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_identity": manifest.source_identity,
        "selector": {"kind": selector_kind, "value": selector_value},
        "source": {
            "path": source_record.path,
            "size": source_record.size,
            "sha256": source_record.sha256,
        },
        "artifacts": _artifact_manifest(artifacts),
    }


def _fit_manifest_budget(
    manifest: GameWorkspaceManifest,
    source_record: WorkspaceFileRecord,
    selector_kind: str,
    selector_value: str,
    artifacts: list[_Artifact],
    max_bytes: int,
) -> tuple[list[_Artifact], bytes]:
    selected = list(artifacts)
    while True:
        manifest_bytes = _canonical_json(
            _pack_manifest(manifest, source_record, selector_kind, selector_value, selected)
        )
        if _artifact_bytes(selected) + len(manifest_bytes) <= max_bytes:
            return selected, manifest_bytes
        optional_index = next(
            (
                index
                for index in range(len(selected) - 1, -1, -1)
                if selected[index].path in _OPTIONAL_FULL_ARTIFACTS
            ),
            None,
        )
        if optional_index is None:
            raise AnalysisPackError("Analysis-pack manifest would exceed the configured budget")
        del selected[optional_index]


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _reject_symlinked_output(output: Path) -> None:
    for candidate in (output, *output.parents):
        if candidate.is_symlink():
            raise AnalysisPackError(
                f"Analysis-pack output path contains a symlink component: {candidate}"
            )


def _write_pack(output: Path, artifacts: list[_Artifact], manifest_bytes: bytes) -> None:
    _reject_symlinked_output(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlinked_output(output)
    if output.exists() and output.is_dir():
        raise AnalysisPackError(f"Analysis-pack output is a directory: {output}")
    temp = output.with_name(f".{output.name}.tmp")
    try:
        with zipfile.ZipFile(temp, "w") as archive:
            for artifact in sorted(artifacts, key=lambda item: item.path):
                archive.writestr(_zip_info(artifact.path), artifact.data)
            archive.writestr(_zip_info("pack-manifest.json"), manifest_bytes)
        temp.replace(output)
    except AnalysisPackError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise AnalysisPackError(f"Unable to write analysis pack: {exc}") from exc
    finally:
        if temp.exists():
            temp.unlink()


def create_analysis_pack(
    workspace_dir: Path | str,
    output_path: Path | str,
    *,
    module: str | None = None,
    function: str | None = None,
    resource: str | None = None,
    max_bytes: int = DEFAULT_PACK_MAX_BYTES,
    context_bytes: int = DEFAULT_CONTEXT_BYTES,
) -> AnalysisPackResult:
    if max_bytes <= 0:
        raise AnalysisPackError("Analysis-pack budget must be positive")
    if context_bytes < 0 or context_bytes > max_bytes:
        raise AnalysisPackError("Analysis-pack context size must be within the configured budget")
    if resource is not None and (module is not None or function is not None):
        raise AnalysisPackError("Resource packs cannot be combined with module/function selectors")
    if module is None and function is None and resource is None:
        raise AnalysisPackError("Select a module, function, or resource for the analysis pack")

    workspace = Path(workspace_dir)
    manifest = load_game_workspace(workspace)
    analysis_root = _analysis_root(workspace)

    if resource is not None:
        source_record = _find_file(manifest, resource)
        normalized = _resource_record(analysis_root, source_record.path)
        artifacts = _resource_artifacts(
            analysis_root,
            source_record,
            normalized,
            max_bytes=max_bytes,
            context_bytes=context_bytes,
        )
        selector_kind = "resource"
        selector_value = source_record.path
    else:
        if module is None:
            if function is None:
                raise AnalysisPackError("Select a module or function for the analysis pack")
            normalized_module = _single_analyzed_module(analysis_root)
            module_path = normalized_module.get("path")
            if not isinstance(module_path, str):
                raise AnalysisPackError("Analyzed module has no logical source path")
            source_record = _find_file(manifest, module_path)
        else:
            source_record = _find_file(manifest, module)
            normalized_module = _module_record(analysis_root, source_record.path)

        if function is None:
            artifacts = _module_artifacts(
                analysis_root,
                workspace,
                source_record,
                normalized_module,
                max_bytes=max_bytes,
            )
            selector_kind = "module"
            selector_value = source_record.path
        else:
            artifacts, selected_function = _function_artifacts(
                analysis_root,
                source_record,
                normalized_module,
                function,
                max_bytes=max_bytes,
                context_bytes=context_bytes,
            )
            selector_kind = "function"
            selected_name = selected_function.get("name")
            selector_value = str(selected_name if selected_name is not None else function)

    artifacts, manifest_bytes = _fit_manifest_budget(
        manifest,
        source_record,
        selector_kind,
        selector_value,
        artifacts,
        max_bytes,
    )
    total_bytes = _artifact_bytes(artifacts)
    output = Path(output_path)
    _write_pack(output, artifacts, manifest_bytes)
    return AnalysisPackResult(
        output_path=output,
        selector_kind=selector_kind,
        selector_value=selector_value,
        artifact_count=len(artifacts),
        total_bytes=total_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )
