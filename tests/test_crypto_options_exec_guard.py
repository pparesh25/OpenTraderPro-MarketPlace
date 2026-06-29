"""The Binance exec half must REFUSE options orders — it implements no options
order route (OPTIONS is absent from its SUPPORTED_SEGMENTS). Without the guard,
_resolve_segment's unknown->SPOT default would attempt a malformed SPOT order on
an option symbol (fail-OPEN). We exec-load the shipped .txt exactly as the host."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentrader")

from opentrader.connectors_v2.data_types import OrderRequest  # noqa: E402

EXEC = (
    Path(__file__).resolve().parents[1]
    / "plugins" / "exec" / "crypto_exchange_exec.txt"
)


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(EXEC.read_text(), str(EXEC), "exec"), ns)  # noqa: S102
    return ns


class _AuthSession:
    """Authenticated, but its client must NOT be reached for a refused order."""

    is_authenticated = True

    @property
    def client(self):                       # pragma: no cover - guard returns first
        raise AssertionError("client touched — guard should have refused first")


def _plugin(ns: dict):
    ExecPlugin = ns["ExecPlugin"]
    p = object.__new__(ExecPlugin)          # skip __init__ (session registry / net)
    p.alias = "acct"                        # account_id derives from INFO.name + alias
    p._session = _AuthSession()
    return p


class TestOptionsOrderRefused:
    def test_resolve_segment_recognises_options(self):
        ns = _load_ns()
        resolve = ns["_resolve_segment"]
        OPTIONS = ns["OPTIONS"]
        for s in ("CRYPTO_OPTIONS", "OPTIONS", "EAPI", "BINANCE_OPTIONS", "BINANCE_EAPI"):
            assert resolve(s) == OPTIONS
        # …and OPTIONS is NOT tradable here, so the order guard rejects it.
        assert OPTIONS not in ns["SUPPORTED_SEGMENTS"]

    def test_place_order_refuses_options_fail_closed(self):
        ns = _load_ns()
        p = _plugin(ns)
        resp = p.place_order(OrderRequest(
            account_id=p.account_id, symbol="BTC-260630-60000-C",
            exchange="CRYPTO_OPTIONS", segment="CRYPTO_OPTIONS",
            side="BUY", order_type="MARKET", quantity=1, product="CNC",
        ))
        assert resp.ok is False
        assert "CRYPTO_OPTIONS" in (resp.error or "")

    def test_tradable_segments_pass_the_guard(self):
        # Regression: spot/USD-M/COIN-M still resolve into SUPPORTED_SEGMENTS, so
        # the new guard does NOT refuse them (it only fails closed for OPTIONS).
        ns = _load_ns()
        resolve = ns["_resolve_segment"]
        supported = ns["SUPPORTED_SEGMENTS"]
        for s in ("CRYPTO_SPOT", "USDM_FUTURES", "COINM_FUTURES", "BINANCE"):
            assert resolve(s) in supported
