from __future__ import annotations

import importlib
import sys

import pytest


def test_phase1_import_does_not_eagerly_import_analysis_engines() -> None:
    sys.modules.pop("spimdisasm", None)
    sys.modules.pop("rabbitizer", None)

    import pspdisasm

    importlib.reload(pspdisasm)
    assert "spimdisasm" not in sys.modules
    assert "rabbitizer" not in sys.modules


def test_load_engines_reports_optional_extra_when_dependencies_are_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from pspdisasm.engines import spim
    from pspdisasm.errors import EngineUnavailableError

    def missing_import(name: str):
        raise ModuleNotFoundError(name=name)

    monkeypatch.setattr(spim.importlib, "import_module", missing_import)

    with pytest.raises(EngineUnavailableError, match=r"pspdisasm\[analysis\]"):
        spim.load_engines()
