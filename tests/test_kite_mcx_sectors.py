"""Tests for the Kite data plugin's MCX sector mapping + stamping.

The plugin ships as a signed ``.txt`` python module; we exec-load it exactly
as the host app does (``exec(compile(src), ns)``) rather than importing it, so
the test exercises the shipped artifact directly. Requires the OpenTrader-Pro
app package on ``sys.path`` (see ``conftest.py``); skips if it can't be found.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentrader")  # app package required to exec-load the plugin

PLUGIN = Path(__file__).resolve().parents[1] / "plugins" / "data" / "kite_broker_data.txt"

# The full, intended set of MCX sector labels. Guards against a typo'd label
# silently drifting into the dict (which would split a sector facet in the UI).
KNOWN_SECTORS = {"Bullion", "Energy", "Base Metals", "Agri-Commodity", "Index"}


def _load_plugin_ns() -> dict:
    ns: dict = {}
    exec(compile(PLUGIN.read_text(), str(PLUGIN), "exec"), ns)  # noqa: S102
    return ns


class _FakeSession:
    """Minimal stand-in for KiteSession: authenticated, canned instrument rows."""

    is_authenticated = True

    def __init__(self, rows_by_exch: dict[str, list[dict]]) -> None:
        self._rows = rows_by_exch

    def get_instruments(self, exchange: str = "NSE") -> list[dict]:
        return self._rows.get(exchange, [])


def _make_plugin(ns: dict, rows_by_exch: dict[str, list[dict]]):
    DataPlugin = ns["DataPlugin"]
    plugin = object.__new__(DataPlugin)  # skip __init__ (session registry / network)
    plugin._session = _FakeSession(rows_by_exch)
    return plugin


def test_mcx_sector_labels_are_known():
    sectors = _load_plugin_ns()["_MCX_SECTORS"]
    assert sectors, "_MCX_SECTORS must not be empty"
    unexpected = {v for v in sectors.values() if v not in KNOWN_SECTORS}
    assert not unexpected, f"unexpected sector labels: {sorted(unexpected)}"


def test_fetch_instruments_stamps_sector():
    ns = _load_plugin_ns()
    mcx_rows = [
        {"tradingsymbol": "GOLD26JULFUT", "name": "GOLD", "instrument_type": "FUT",
         "expiry": "2026-07-28", "lot_size": 100, "tick_size": 1.0},
        {"tradingsymbol": "WHATSIT26JULFUT", "name": "SOMENEWCMDTY",
         "instrument_type": "FUT", "expiry": "2026-07-28", "lot_size": 1,
         "tick_size": 1.0},
    ]
    nse_rows = [
        {"tradingsymbol": "RELIANCE", "name": "RELIANCE", "instrument_type": "EQ",
         "lot_size": 1, "tick_size": 0.05},
    ]
    plugin = _make_plugin(ns, {"MCX": mcx_rows, "NSE": nse_rows})

    mcx = {r.symbol: r for r in plugin.fetch_instruments("MCX")}
    assert mcx["GOLD26JULFUT"].sector == "Bullion"       # mapped commodity
    assert mcx["WHATSIT26JULFUT"].sector == "Other"      # unknown → Other bucket

    nse = plugin.fetch_instruments("NSE_EQ")
    assert nse and all(r.sector is None for r in nse)     # non-MCX → no sector
