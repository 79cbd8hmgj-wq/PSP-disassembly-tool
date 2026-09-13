from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Iterable

from .queue import QueuedFunction
from .workspace import decompilation_root


def write_match_status_report(workspace_dir: Path | str, functions: Iterable[QueuedFunction]) -> Path:
    """Write a flat CSV summary of every function's current decompilation status.

    Reports are derived, disposable output: regenerated wholesale on each call
    from persisted state, never incrementally patched.
    """
    reports_dir = decompilation_root(workspace_dir) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / "match_status.csv"

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["module", "function", "address", "status", "attempts", "best_match_percent", "best_attempt_id"])
    for function in sorted(functions, key=lambda item: (item.module.casefold(), item.function.casefold(), item.address)):
        state = function.state
        writer.writerow(
            [
                state.module,
                state.function,
                f"0x{state.address:08X}",
                state.status,
                state.attempts,
                "" if state.best_match_percent is None else f"{state.best_match_percent:.2f}",
                state.best_attempt_id or "",
            ]
        )
    path.write_text(buffer.getvalue(), encoding="utf-8")
    return path
