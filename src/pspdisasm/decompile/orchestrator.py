from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Sequence

from ..decompiler import DEFAULT_M2C_TARGET, decompile_project_function, resolve_m2c_command
from ..errors import (
    BuildFailedError,
    BuildToolchainUnavailableError,
    DecompilationError,
    DecompilerUnavailableError,
    MatcherUnavailableError,
    MatchingError,
    UnsupportedFunctionError,
)
from ..matcher import match_project_function, resolve_match_function
from ..model import DecompilationAttempt, FunctionDecompilationState
from .queue import DecompilationStatus, QueuedFunction
from .toolchain import BuildToolchain
from .workspace import save_function_state

DEFAULT_MAX_ATTEMPTS = 2
DEFAULT_TIMEOUT_SECONDS = 120.0


class AttemptOutcome(str, Enum):
    """Finer-grained than DecompilationStatus: an attempt-level diagnostic, not the coarse function status."""

    DECOMPILED = "decompiled"
    DECOMPILATION_FAILED = "decompilation_failed"
    BUILD_FAILED = "build_failed"
    MATCH_FAILED = "match_failed"
    MATCHED_PARTIAL = "matched_partial"
    MATCHED_EXACT = "matched_exact"


@dataclass(frozen=True, slots=True)
class RetryVariant:
    reason: str
    contexts: tuple[Path, ...]
    target: str


def default_variants(contexts: Sequence[Path | str], target: str) -> list[RetryVariant]:
    """The only two knobs decompile_project_function actually exposes: which
    context files are supplied, and the m2c target triple. No other variance
    is fabricated."""
    variants = [RetryVariant(reason="default", contexts=(), target=target)]
    resolved_contexts = tuple(Path(context) for context in contexts)
    if resolved_contexts:
        variants.append(RetryVariant(reason="with_context", contexts=resolved_contexts, target=target))
    return variants


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_m2c_version(command: Sequence[str]) -> str | None:
    """Pure function of the resolved command path, mirroring the equivalent
    peek-at-a-nearby-pyproject.toml logic already duplicated in decompiler.py
    and matcher.py for their own backends -- computed without executing m2c,
    so it can be part of the attempt identity before deciding whether to run."""
    if not command:
        return None
    candidate = Path(command[-1])
    if candidate.name != "m2c.py":
        return None
    pyproject = candidate.parent / "pyproject.toml"
    try:
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    version = payload.get("project", {}).get("version")
    return version if isinstance(version, str) else None


def compute_attempt_id(
    *,
    function: str,
    address: int,
    assembly_sha256: str,
    context_sha256: list[str],
    m2c_command: list[str],
    m2c_version: str | None,
    target: str,
    toolchain_identity: dict[str, object] | None,
) -> str:
    """Content-derived attempt identity -- never wall-clock. Any change to
    assembly, context, m2c command/version, target, or toolchain identity
    produces a different id, which is the entire cache-invalidation mechanism:
    there is no separate "invalidate" step, just "this exact id was not seen
    before."""
    payload = {
        "function": function,
        "address": address,
        "assembly_sha256": assembly_sha256,
        "context_sha256": context_sha256,
        "m2c_command": m2c_command,
        "m2c_version": m2c_version,
        "target": target,
        "toolchain_identity": toolchain_identity,
    }
    return _sha256_text(_canonical_json(payload))[:16]


def _rank(attempt: DecompilationAttempt) -> tuple:
    return (
        0 if attempt.match_exact else 1,
        -(attempt.match_similarity_percent if attempt.match_similarity_percent is not None else -1.0),
        (attempt.changed_rows or 0) + (attempt.added_rows or 0) + (attempt.removed_rows or 0),
        attempt.attempt_id,
    )


def select_best_attempt(attempts: Sequence[DecompilationAttempt]) -> DecompilationAttempt | None:
    if not attempts:
        return None
    return min(attempts, key=_rank)


def _status_from_best(best: DecompilationAttempt | None) -> str:
    if best is None:
        return DecompilationStatus.BLOCKED.value
    if best.match_exact:
        return DecompilationStatus.MATCHED_EXACT.value
    if best.match_similarity_percent is not None:
        return DecompilationStatus.MATCHED_PARTIAL.value
    if best.candidate_sha256 is not None:
        return DecompilationStatus.BUILD_FAILED.value
    return DecompilationStatus.BLOCKED.value


def _function_has_known_references(project_dir: Path, function_name: str) -> bool:
    path = project_dir / "metadata" / "references.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return False
    return isinstance(payload, list) and any(
        isinstance(item, dict) and item.get("source_function") == function_name for item in payload
    )


def run_function(
    queued: QueuedFunction,
    *,
    m2c_path: Path | str | None = None,
    contexts: Sequence[Path | str] = (),
    target: str = DEFAULT_M2C_TARGET,
    toolchain: BuildToolchain,
    asm_differ_path: Path | str | None = None,
    objdump_path: Path | str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    force: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> FunctionDecompilationState:
    """Run the bounded generate -> build -> match retry loop for one function.

    Every attempt is appended to attempt_history and never deleted or
    overwritten. Stops early on an exact match, on a globally-missing
    backend/toolchain (BLOCKED), or once the bounded variant matrix /
    max_attempts is exhausted -- never an infinite loop.
    """
    match_function = resolve_match_function(queued.project_dir, queued.function)
    if not match_function.instructions:
        raise UnsupportedFunctionError(f"function {queued.function!r} has no instructions to decompile")

    try:
        m2c_command = resolve_m2c_command(m2c_path)
    except DecompilerUnavailableError as exc:
        return replace(
            queued.state,
            status=DecompilationStatus.BLOCKED.value,
            last_failure=str(exc),
        )
    m2c_version = _probe_m2c_version(m2c_command)

    variants = default_variants(contexts, target)[:max_attempts]
    attempts = list(queued.state.attempt_history)
    existing_ids = {attempt.attempt_id for attempt in attempts}
    toolchain_identity = toolchain.identity()
    has_known_references = _function_has_known_references(queued.project_dir, queued.function)

    for variant in variants:
        try:
            context_sha256 = [_sha256_file(path) for path in variant.contexts]
        except OSError as exc:
            attempt = DecompilationAttempt(
                attempt_id=compute_attempt_id(
                    function=queued.function, address=queued.address, assembly_sha256="unavailable",
                    context_sha256=[], m2c_command=m2c_command, m2c_version=m2c_version, target=variant.target,
                    toolchain_identity=toolchain_identity,
                ),
                variant_reason=variant.reason,
                assembly_sha256="unavailable",
                context_sha256=[],
                m2c_command=m2c_command,
                m2c_version=m2c_version,
                target=variant.target,
                outcome=AttemptOutcome.DECOMPILATION_FAILED.value,
                diagnostics=[f"context generation failed: {exc}"],
            )
            if attempt.attempt_id not in existing_ids:
                attempts.append(attempt)
                existing_ids.add(attempt.attempt_id)
            continue

        # decompile_project_function re-reads and validates the assembly itself;
        # we only need its hash up front for the attempt identity, so re-derive
        # it from the already-loaded MatchFunction's own assembly text via the
        # same project-functions.json this function came from.
        assembly_sha256 = _sha256_text(_assembly_text_for(queued.project_dir, queued.function))

        attempt_id = compute_attempt_id(
            function=queued.function,
            address=queued.address,
            assembly_sha256=assembly_sha256,
            context_sha256=context_sha256,
            m2c_command=m2c_command,
            m2c_version=m2c_version,
            target=variant.target,
            toolchain_identity=toolchain_identity,
        )
        if attempt_id in existing_ids and not force:
            continue

        attempt = _run_one_attempt(
            queued,
            variant=variant,
            attempt_id=attempt_id,
            assembly_sha256=assembly_sha256,
            context_sha256=context_sha256,
            m2c_path=m2c_path,
            m2c_command=m2c_command,
            m2c_version=m2c_version,
            toolchain=toolchain,
            toolchain_identity=toolchain_identity,
            asm_differ_path=asm_differ_path,
            objdump_path=objdump_path,
            timeout=timeout,
            has_known_references=has_known_references,
        )
        if attempt is None:
            # A globally-missing toolchain/matcher backend: stop trying variants.
            return replace(
                queued.state,
                attempts=len(attempts),
                status=DecompilationStatus.BLOCKED.value,
                last_failure="build or match backend is unavailable",
                attempt_history=attempts,
            )
        attempts.append(attempt)
        existing_ids.add(attempt.attempt_id)
        if attempt.match_exact:
            break

    best = select_best_attempt(attempts)
    final_status = _status_from_best(best)
    last_failure = None if best is not None and best.match_exact else (best.diagnostics[-1] if best and best.diagnostics else None)

    return FunctionDecompilationState(
        module=queued.module,
        function=queued.function,
        address=queued.address,
        status=final_status,
        attempts=len(attempts),
        best_attempt_id=best.attempt_id if best else None,
        best_match_percent=best.match_similarity_percent if best else None,
        static_confidence=queued.state.static_confidence,
        static_evidence=queued.state.static_evidence,
        runtime_status=queued.state.runtime_status,
        last_failure=last_failure,
        attempt_history=attempts,
    )


def _assembly_text_for(project_dir: Path, function_name: str) -> str:
    path = project_dir / "metadata" / "functions.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload:
        if isinstance(entry, dict) and entry.get("name") == function_name:
            return str(entry.get("assembly", ""))
    return ""


def _run_one_attempt(
    queued: QueuedFunction,
    *,
    variant: RetryVariant,
    attempt_id: str,
    assembly_sha256: str,
    context_sha256: list[str],
    m2c_path: Path | str | None,
    m2c_command: list[str],
    m2c_version: str | None,
    toolchain: BuildToolchain,
    toolchain_identity: dict[str, object],
    asm_differ_path: Path | str | None,
    objdump_path: Path | str | None,
    timeout: float,
    has_known_references: bool,
) -> DecompilationAttempt | None:
    base_kwargs = dict(
        attempt_id=attempt_id,
        variant_reason=variant.reason,
        assembly_sha256=assembly_sha256,
        context_sha256=context_sha256,
        m2c_command=m2c_command,
        m2c_version=m2c_version,
        target=variant.target,
        toolchain_name=toolchain.name,
        toolchain_identity=toolchain_identity,
    )

    output_c = queued.project_dir / "src" / "nonmatching" / f"{_safe_stem(queued.function)}.{attempt_id}.c"
    try:
        decompilation = decompile_project_function(
            queued.project_dir,
            queued.function,
            m2c_path=m2c_path,
            contexts=variant.contexts,
            output_path=output_c,
            target=variant.target,
        )
    except DecompilerUnavailableError:
        return None
    except DecompilationError as exc:
        return DecompilationAttempt(
            outcome=AttemptOutcome.DECOMPILATION_FAILED.value,
            diagnostics=[str(exc)],
            **base_kwargs,
        )

    candidate_sha256 = _sha256_bytes(decompilation.output_path.read_bytes())
    output_object = queued.project_dir / "build" / "nonmatching" / f"{_safe_stem(queued.function)}.{attempt_id}.o"
    try:
        build_result = toolchain.compile_function(
            decompilation.output_path, output=output_object, project=queued.project_dir, timeout=timeout
        )
    except BuildToolchainUnavailableError:
        return None
    except BuildFailedError as exc:
        return DecompilationAttempt(
            outcome=AttemptOutcome.BUILD_FAILED.value,
            candidate_sha256=candidate_sha256,
            diagnostics=[*decompilation.warnings, str(exc)],
            artifact_paths={"candidate_c": str(decompilation.output_path)},
            **base_kwargs,
        )

    try:
        match_result = match_project_function(
            queued.project_dir,
            queued.function,
            candidate_object=build_result.output_path,
            asm_differ_path=asm_differ_path,
            objdump_path=objdump_path,
            timeout=timeout,
        )
    except MatcherUnavailableError:
        return None
    except MatchingError as exc:
        return DecompilationAttempt(
            outcome=AttemptOutcome.MATCH_FAILED.value,
            candidate_sha256=candidate_sha256,
            object_sha256=build_result.object_sha256,
            diagnostics=[*decompilation.warnings, *build_result.diagnostics, str(exc)],
            artifact_paths={"candidate_c": str(decompilation.output_path), "object": str(build_result.output_path)},
            **base_kwargs,
        )

    match_exact = match_result.raw_score == 0
    return DecompilationAttempt(
        outcome=(AttemptOutcome.MATCHED_EXACT.value if match_exact else AttemptOutcome.MATCHED_PARTIAL.value),
        candidate_sha256=candidate_sha256,
        object_sha256=build_result.object_sha256,
        match_raw_score=match_result.raw_score,
        match_max_score=match_result.max_score,
        match_similarity_percent=match_result.similarity_percent,
        match_exact=match_exact,
        matching_rows=match_result.matching_rows,
        changed_rows=match_result.changed_rows,
        added_rows=match_result.added_rows,
        removed_rows=match_result.removed_rows,
        reference_lacks_relocations=has_known_references,
        diagnostics=[*decompilation.warnings, *build_result.diagnostics, *match_result.warnings],
        artifact_paths={
            "candidate_c": str(decompilation.output_path),
            "object": str(build_result.output_path),
            "match_metadata": str(match_result.metadata_path),
        },
        **base_kwargs,
    )


def _safe_stem(function: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in function).strip("._")
    return cleaned or "function"


def run_and_persist(workspace_dir: Path | str, queued: QueuedFunction, **kwargs: object) -> FunctionDecompilationState:
    """run_function() plus atomic persistence -- the entry point orchestrator callers should use."""
    try:
        state = run_function(queued, **kwargs)
    except UnsupportedFunctionError as exc:
        state = replace(queued.state, status=DecompilationStatus.UNSUPPORTED.value, last_failure=str(exc))
    save_function_state(workspace_dir, state)
    return state
