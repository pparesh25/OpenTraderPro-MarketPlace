"""Make the OpenTrader-Pro app package importable for plugin tests.

The data-plugin ``.txt`` modules import ``opentrader.*`` (the host app's V2
plugin contract / data types), so any test that exec-loads one needs the app
package on ``sys.path``. The app is not pip-installed alongside this repo; we
locate it via ``OPENTRADER_PRO_PATH`` or the conventional sibling checkout
``../OpenTrader-Pro``. If neither is found the plugin tests skip (see
``pytest.importorskip('opentrader')`` in the test module) so signature-only CI
without the app present stays green.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _locate_app_repo() -> Path | None:
    candidates: list[Path] = []
    env = os.environ.get("OPENTRADER_PRO_PATH")
    if env:
        candidates.append(Path(env))
    repo_root = Path(__file__).resolve().parents[1]
    candidates.append(repo_root.parent / "OpenTrader-Pro")
    for c in candidates:
        if (c / "opentrader" / "__init__.py").exists():
            return c
    return None


def pytest_configure(config) -> None:  # noqa: ARG001
    try:
        import opentrader  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    app = _locate_app_repo()
    if app is not None:
        sys.path.insert(0, str(app))
