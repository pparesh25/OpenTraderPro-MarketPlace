"""Tests for the Binance data plugin's perp-vs-dated classification and the
spot / USD-M / COIN-M live-ticker socket routing.

The plugin ships as a signed ``.txt`` python module; we exec-load it exactly as
the host app does (``exec(compile(src), ns)``) rather than importing it, so the
test exercises the shipped artifact directly. Requires the OpenTrader-Pro app
package on ``sys.path`` (see ``conftest.py``); skips if it can't be found.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("opentrader")  # app package required to exec-load the plugin

from opentrader.domain import InstrumentType  # noqa: E402

PLUGIN = (
    Path(__file__).resolve().parents[1]
    / "plugins" / "data" / "crypto_exchange_data.txt"
)

# Binance ships perpetual contracts with this year-2100 sentinel deliveryDate.
PERP_SENTINEL_MS = 4133404800000


def _ms(y: int, m: int, d: int) -> int:
    return int(datetime(y, m, d, tzinfo=timezone.utc).timestamp() * 1000)


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(PLUGIN.read_text(), str(PLUGIN), "exec"), ns)  # noqa: S102
    return ns


def _fut_info(symbol: str, base: str, quote: str, ctype: str, delivery_ms: int) -> dict:
    """A minimal Binance futures exchangeInfo symbol row."""
    return {
        "symbol": symbol, "baseAsset": base, "quoteAsset": quote,
        "contractType": ctype, "deliveryDate": delivery_ms,
        "status": "TRADING", "filters": [],
    }


class _FakeSession:
    """Canned exchange-info, authenticated. ``rows_by_seg`` =
    ``{segment: {SYMBOL: exchangeInfo_dict}}``."""

    is_authenticated = True

    def __init__(self, rows_by_seg: dict) -> None:
        self._rows = rows_by_seg

    def load_symbols(self, segment: str, force: bool = False) -> None:
        pass

    def active_symbols(self, segment: str, quote_asset: str = "") -> list[str]:
        return list(self._rows.get(segment, {}).keys())

    def symbol_info(self, symbol: str, segment: str) -> dict | None:
        return self._rows.get(segment, {}).get(symbol.upper())


def _make_plugin(ns: dict, session):
    DataPlugin = ns["DataPlugin"]
    p = object.__new__(DataPlugin)        # skip __init__ (session registry / net)
    p._session = session
    return p


# ── F1: perp-vs-dated classification by real deliveryDate ─────────────────────
class TestPerpDatedClassification:
    def test_tradifi_perpetual_is_perp_not_dated(self):
        ns = _load_ns()
        USDM = ns["USDM"]
        p = _make_plugin(ns, _FakeSession({USDM: {
            "BTCUSDT": _fut_info("BTCUSDT", "BTC", "USDT", "PERPETUAL", PERP_SENTINEL_MS),
            # Tokenized-equity perp — Binance reports contractType TRADIFI_PERPETUAL.
            "AAPLUSDT": _fut_info("AAPLUSDT", "AAPL", "USDT", "TRADIFI_PERPETUAL", PERP_SENTINEL_MS),
            # A genuine quarterly with a real delivery date.
            "BTCUSDT_261225": _fut_info("BTCUSDT_261225", "BTC", "USDT", "CURRENT_QUARTER", _ms(2026, 12, 25)),
        }}))
        recs = {r.symbol: r for r in p.fetch_instruments(USDM)}

        # The tokenized-stock perp must be a PERP with no expiry (the bug typed
        # it CRYPTO_FUTURE because contractType != literal "PERPETUAL").
        assert recs["AAPLUSDT"].instrument_type is InstrumentType.CRYPTO_PERP
        assert recs["AAPLUSDT"].expiry is None
        # Bare PERPETUAL → perp.
        assert recs["BTCUSDT"].instrument_type is InstrumentType.CRYPTO_PERP
        assert recs["BTCUSDT"].expiry is None
        # Only a real deliveryDate makes it dated.
        assert recs["BTCUSDT_261225"].instrument_type is InstrumentType.CRYPTO_FUTURE
        assert recs["BTCUSDT_261225"].expiry is not None
        assert recs["BTCUSDT_261225"].underlying_symbol == "BTC"

    def test_dump_invariant_dated_future_always_has_expiry(self):
        ns = _load_ns()
        USDM, COINM = ns["USDM"], ns["COINM"]
        rows = {
            USDM: {
                "AAPLUSDT": _fut_info("AAPLUSDT", "AAPL", "USDT", "TRADIFI_PERPETUAL", PERP_SENTINEL_MS),
                "ETHUSDT_261225": _fut_info("ETHUSDT_261225", "ETH", "USDT", "NEXT_QUARTER", _ms(2026, 12, 25)),
            },
            COINM: {
                "BTCUSD_PERP": _fut_info("BTCUSD_PERP", "BTC", "USD", "PERPETUAL", PERP_SENTINEL_MS),
                "BTCUSD_261225": _fut_info("BTCUSD_261225", "BTC", "USD", "CURRENT_QUARTER", _ms(2026, 12, 25)),
            },
        }
        p = _make_plugin(ns, _FakeSession(rows))
        for seg in (USDM, COINM):
            for r in p.fetch_instruments(seg):
                if r.instrument_type is InstrumentType.CRYPTO_FUTURE:
                    assert r.expiry is not None, f"{r.symbol}: dated future with NULL expiry"


# ── F5: live-ticker socket routing (spot vs USD-M vs COIN-M) ──────────────────
class _RecordingWS:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def start(self) -> None:
        pass

    def start_symbol_ticker_socket(self, callback, symbol) -> str:
        self.calls.append(("spot", symbol))
        return f"spot:{symbol}"

    def start_symbol_ticker_futures_socket(self, callback, symbol, futures_type) -> str:
        self.calls.append((str(futures_type), symbol))
        return f"fut:{symbol}"


class _WsSession:
    is_authenticated = True

    def __init__(self, ws) -> None:
        self._ws = ws

    def create_ws_manager(self):
        return self._ws


class TestLiveSocketRouting:
    def _plugin(self, ns: dict, ws):
        DataPlugin = ns["DataPlugin"]
        p = object.__new__(DataPlugin)
        p.alias = "test"
        p._session = _WsSession(ws)
        p._bm = None
        p._conn_keys = {}
        p._symbol_exchange = {}
        p._on_tick = None
        p._last_cum_volume = {}
        return p

    def test_spot_usdm_coinm_use_distinct_sockets(self):
        ns = _load_ns()
        ws = _RecordingWS()
        p = self._plugin(ns, ws)
        p.subscribe_realtime(
            [
                ("BTCUSDT", "CRYPTO_SPOT"),
                ("ETHUSDT", "USDM_FUTURES"),
                ("BTCUSD_PERP", "COINM_FUTURES"),
            ],
            on_tick=lambda _t: None,
        )
        kind_by_sym = {sym: kind for kind, sym in ws.calls}
        # Spot uses the spot ticker; futures use the futures ticker with the
        # right venue (USD_M / COIN_M) — pre-fix all three hit the spot socket.
        assert kind_by_sym["btcusdt"] == "spot"
        assert "USD_M" in kind_by_sym["ethusdt"]
        assert "COIN_M" in kind_by_sym["btcusd_perp"]

    def test_futures_ticker_prev_close_derived_for_change_pct(self):
        """The futures ticker has no 'x' (prev close); _on_ticker_message derives
        it from c - p (24h change) so Market Watch change% works for futures."""
        ns = _load_ns()
        p = self._plugin(ns, _RecordingWS())
        captured: list = []
        p._on_tick = captured.append
        p._symbol_exchange = {"ETHUSDT": "USDM_FUTURES"}
        # Futures 24h ticker payload: last 'c', 24h change 'p', no 'x'.
        p._on_ticker_message({
            "e": "24hrTicker", "s": "ETHUSDT", "c": "110", "p": "10",
            "o": "100", "h": "115", "l": "95", "v": "1000", "E": 1,
        })
        assert captured, "no tick emitted"
        tick = captured[0]
        assert tick.prev_close == pytest.approx(100.0)   # 110 - 10
