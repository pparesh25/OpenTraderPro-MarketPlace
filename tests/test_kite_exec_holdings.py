"""S5 (CNC) — kite get_holdings must report the SELLABLE size.

Kite splits a holding into ``quantity`` (settled, in demat) and
``t1_quantity`` (bought T-1, awaiting settlement); Zerodha allows selling
both, so the plugin sums them. Reporting only the settled part would make
the app's exit-size resolution under-flatten a position bought yesterday.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("opentrader")

EXEC = (
    Path(__file__).resolve().parents[1] / "plugins" / "exec" / "kite_broker_exec.txt"
)


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(EXEC.read_text(), str(EXEC), "exec"), ns)  # noqa: S102
    return ns


class _FakeKite:
    def __init__(self, rows):
        self._rows = rows

    def holdings(self):
        return self._rows


class _FakeSession:
    is_authenticated = True

    def __init__(self, rows):
        self.kite_exec = _FakeKite(rows)


def _plugin_with(rows):
    ns = _load_ns()
    cls = ns["ExecPlugin"]
    plugin = cls.__new__(cls)          # skip __init__ (no session registry)
    plugin._session = _FakeSession(rows)
    plugin._err_state = {}
    plugin._proxy_fail_count = 0
    plugin._proxy_open_at = None
    plugin._monotonic = time.monotonic
    return plugin


def _row(**over):
    row = {
        "tradingsymbol": "RELIANCE", "exchange": "NSE",
        "quantity": 40, "t1_quantity": 10,
        "average_price": 90.0, "last_price": 110.0, "pnl": 800.0,
    }
    row.update(over)
    return row


class TestKiteHoldingsSellableQuantity:
    def test_quantity_sums_settled_plus_t1(self):
        plugin = _plugin_with([_row()])
        holdings = plugin.get_holdings()
        assert len(holdings) == 1
        assert holdings[0].quantity == 50          # 40 settled + 10 T1
        assert holdings[0].symbol == "RELIANCE"

    def test_missing_or_null_t1_defaults_to_settled_only(self):
        rows = [
            _row(tradingsymbol="A"),                       # t1 present (10)
            _row(tradingsymbol="B", t1_quantity=None),     # null t1
        ]
        del rows[1]["t1_quantity"]
        rows.append(_row(tradingsymbol="C", t1_quantity=None))
        plugin = _plugin_with(rows)
        by_symbol = {h.symbol: h.quantity for h in plugin.get_holdings()}
        assert by_symbol == {"A": 50, "B": 40, "C": 40}
