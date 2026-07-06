"""Kite plugin: a derivative's ``underlying_exchange`` must be the underlying's
CASH exchange, not the derivative's own F&O/currency exchange.

Regression for the V3-P4 regime gap — the old code stamped the derivative's own
``exch`` (e.g. ``"NFO"``), so the app's underlying-record lookup (a NIFTY/
RELIANCE derivative -> its cash underlying for the regime UNDERLYING_SPOT/FUTURE
edge) searched the wrong exchange and silently missed. The plugin ships as a
signed ``.txt``; we exec-load it exactly as the host app does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentrader")  # app package required to exec-load the plugin

PLUGIN = Path(__file__).resolve().parents[1] / "plugins" / "data" / "kite_broker_data.txt"


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(PLUGIN.read_text(), str(PLUGIN), "exec"), ns)  # noqa: S102
    return ns


class _FakeSession:
    is_authenticated = True

    def __init__(self, rows_by_exch: dict[str, list[dict]]) -> None:
        self._rows = rows_by_exch

    def get_instruments(self, exchange: str = "NSE") -> list[dict]:
        return self._rows.get(exchange, [])


def _plugin(ns: dict, rows_by_exch: dict[str, list[dict]]):
    DataPlugin = ns["DataPlugin"]
    plugin = object.__new__(DataPlugin)   # skip __init__ (session registry / network)
    plugin._session = _FakeSession(rows_by_exch)
    return plugin


def _fut(tsym, name):
    return {"tradingsymbol": tsym, "name": name, "instrument_type": "FUT",
            "expiry": "2026-07-28", "lot_size": 1, "tick_size": 0.05}


def test_nfo_derivative_underlying_exchange_is_nse():
    # NSE F&O (NFO) -> the underlying index/stock lists on NSE, not NFO.
    recs = _plugin(_load_ns(), {"NFO": [_fut("NIFTY26JULFUT", "NIFTY")]}
                   ).fetch_instruments("NFO")
    r = {x.symbol: x for x in recs}["NIFTY26JULFUT"]
    # M3 name-fix: the Kite ``name`` root "NIFTY" is aliased to the tradable
    # index symbol "NIFTY 50" the app ingests the index under, so the regime
    # index-trend / UNDERLYING_FUTURE edge resolves (was raw "NIFTY" -> never
    # matched -> silently ungated).
    assert r.underlying_symbol == "NIFTY 50"
    assert r.underlying_exchange == "NSE"   # was wrongly "NFO"


def test_bfo_derivative_underlying_exchange_is_bse():
    recs = _plugin(_load_ns(), {"BFO": [_fut("SENSEX26JULFUT", "SENSEX")]}
                   ).fetch_instruments("BFO")
    r = {x.symbol: x for x in recs}["SENSEX26JULFUT"]
    assert r.underlying_exchange == "BSE"


def test_cds_currency_derivative_underlying_exchange_is_nse():
    recs = _plugin(_load_ns(), {"CDS": [_fut("USDINR26JULFUT", "USDINR")]}
                   ).fetch_instruments("CDS")
    r = {x.symbol: x for x in recs}["USDINR26JULFUT"]
    assert r.underlying_exchange == "NSE"


def test_mcx_commodity_derivative_underlying_exchange_stays_mcx():
    # A commodity's underlying shares the derivative's exchange (both MCX) —
    # intentionally NOT remapped.
    recs = _plugin(_load_ns(), {"MCX": [_fut("GOLD26JULFUT", "GOLD")]}
                   ).fetch_instruments("MCX")
    r = {x.symbol: x for x in recs}["GOLD26JULFUT"]
    assert r.underlying_exchange == "MCX"


def test_cash_equity_has_no_underlying_exchange():
    rows = {"NSE": [{"tradingsymbol": "RELIANCE", "name": "RELIANCE",
                     "instrument_type": "EQ", "lot_size": 1, "tick_size": 0.05}]}
    recs = _plugin(_load_ns(), rows).fetch_instruments("NSE_EQ")
    assert recs and all(r.underlying_exchange is None for r in recs)


# ── M3: underlying_symbol index-name alias (regime resolution fix) ──────────
class TestUnderlyingSymbolIndexAlias:
    """A derivative's ``underlying_symbol`` must equal the tradable index symbol
    the app ingests the index under ("NIFTY 50"), not Kite's short F&O root
    ("NIFTY") — else the regime index-trend / UNDERLYING_FUTURE edge never
    resolves and the per-symbol gate passes ungated. Non-index underlyings
    (stocks, commodities, currency pairs) are already their own tradable symbol
    and MUST pass through unchanged."""

    def _underlying(self, exch, tsym, name):
        recs = _plugin(_load_ns(), {exch: [_fut(tsym, name)]}).fetch_instruments(exch)
        return {x.symbol: x for x in recs}[tsym].underlying_symbol

    def test_nifty_root_aliased_to_tradable_index(self):
        assert self._underlying("NFO", "NIFTY26JULFUT", "NIFTY") == "NIFTY 50"

    def test_banknifty_root_aliased(self):
        assert self._underlying("NFO", "BANKNIFTY26JULFUT", "BANKNIFTY") == "NIFTY BANK"

    def test_finnifty_root_aliased(self):
        assert self._underlying("NFO", "FINNIFTY26JULFUT", "FINNIFTY") == "NIFTY FIN SERVICE"

    def test_stock_underlying_passes_through_unchanged(self):
        # A stock future's underlying already IS its tradable cash symbol.
        assert self._underlying("NFO", "RELIANCE26JULFUT", "RELIANCE") == "RELIANCE"

    def test_commodity_underlying_passes_through_unchanged(self):
        assert self._underlying("MCX", "GOLD26JULFUT", "GOLD") == "GOLD"

    def test_currency_pair_passes_through_unchanged(self):
        # Left as the pair name so the app's fx_dxy_sign / DXY chain resolves.
        assert self._underlying("CDS", "USDINR26JULFUT", "USDINR") == "USDINR"

    def test_bse_sensex_identity_passes_through(self):
        # SENSEX ingests under the same name on BSE — no alias needed.
        assert self._underlying("BFO", "SENSEX26JULFUT", "SENSEX") == "SENSEX"
