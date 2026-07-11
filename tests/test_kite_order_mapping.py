"""S6 — kite order placement: SL/SL-M mapping + strict product handling.

Kite Connect accepts ONLY MARKET / LIMIT / SL / SL-M. The pre-S6 identity map
passed the app's "STOP"/"STOP_LIMIT" verbatim, so every live stop order was an
InputException reject. And an unknown/empty product silently became "CNC" —
turning e.g. an NRML F&O exit into a broker-rejected delivery order.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("opentrader")

from opentrader.connectors_v2.data_types import AccountId, OrderRequest  # noqa: E402

EXEC = (
    Path(__file__).resolve().parents[1] / "plugins" / "exec" / "kite_broker_exec.txt"
)


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(EXEC.read_text(), str(EXEC), "exec"), ns)  # noqa: S102
    return ns


class _FakeKite:
    def __init__(self):
        self.placed: list[dict] = []
        self.book: list[dict] = []

    def place_order(self, **params):
        self.placed.append(params)
        return "ORD1"

    def orders(self):
        return self.book


class _FakeSession:
    is_authenticated = True
    has_proxy = False

    def __init__(self):
        self.kite_exec = _FakeKite()


def _plugin():
    ns = _load_ns()
    cls = ns["ExecPlugin"]
    plugin = cls.__new__(cls)
    plugin.alias = "t"
    plugin._session = _FakeSession()
    plugin._err_state = {}
    plugin._proxy_fail_count = 0
    plugin._proxy_open_at = None
    plugin._monotonic = time.monotonic
    return plugin


def _request(**over):
    base = dict(
        account_id=AccountId("zerodha", "t"),
        symbol="RELIANCE", exchange="NSE", segment="NSE_EQ",
        side="BUY", order_type="MARKET", quantity=10, product="MIS",
        price=None, trigger_price=None,
    )
    base.update(over)
    return OrderRequest(**base)


class TestOrderTypeMapping:
    def test_stop_limit_maps_to_sl_with_price_and_trigger(self):
        plugin = _plugin()
        resp = plugin.place_order(_request(
            order_type="STOP_LIMIT", price=99.5, trigger_price=100.0,
        ))
        assert resp.ok
        sent = plugin._session.kite_exec.placed[-1]
        assert sent["order_type"] == "SL"
        assert sent["price"] == 99.5
        assert sent["trigger_price"] == 100.0
        assert "market_protection" not in sent

    def test_stop_maps_to_sl_m_trigger_only(self):
        plugin = _plugin()
        resp = plugin.place_order(_request(
            order_type="STOP", price=99.5, trigger_price=100.0,
        ))
        assert resp.ok
        sent = plugin._session.kite_exec.placed[-1]
        assert sent["order_type"] == "SL-M"
        assert sent["price"] is None            # stop-MARKET carries no price
        assert sent["trigger_price"] == 100.0
        assert sent["market_protection"] == -1

    def test_market_and_limit_unchanged(self):
        plugin = _plugin()
        plugin.place_order(_request(order_type="MARKET"))
        market = plugin._session.kite_exec.placed[-1]
        assert market["order_type"] == "MARKET"
        assert market["market_protection"] == -1
        plugin.place_order(_request(order_type="LIMIT", price=101.0))
        limit = plugin._session.kite_exec.placed[-1]
        assert limit["order_type"] == "LIMIT" and limit["price"] == 101.0

    def test_order_book_reverse_maps_sl_codes(self):
        plugin = _plugin()
        plugin._session.kite_exec.book = [
            {
                "order_id": 1, "tradingsymbol": "R", "exchange": "NSE",
                "transaction_type": "SELL", "quantity": 5,
                "filled_quantity": 0, "order_type": "SL", "product": "MIS",
                "status": "TRIGGER PENDING", "price": 99.0,
                "trigger_price": 100.0, "order_timestamp": "2026-01-05T10:00:00",
            },
            {
                "order_id": 2, "tradingsymbol": "R", "exchange": "NSE",
                "transaction_type": "SELL", "quantity": 5,
                "filled_quantity": 0, "order_type": "SL-M", "product": "MIS",
                "status": "OPEN", "price": None,
                "trigger_price": 100.0, "order_timestamp": "2026-01-05T10:00:00",
            },
        ]
        records = plugin.get_order_book()
        assert [r.order_type for r in records] == ["STOP_LIMIT", "STOP"]


class TestStrictProduct:
    def test_unknown_product_rejects_loudly_not_cnc(self):
        plugin = _plugin()
        resp = plugin.place_order(_request(product="BO"))
        assert not resp.ok
        assert "unknown product" in resp.error
        assert plugin._session.kite_exec.placed == []   # nothing sent

    def test_empty_product_rejects(self):
        plugin = _plugin()
        resp = plugin.place_order(_request(product=""))
        assert not resp.ok
        assert plugin._session.kite_exec.placed == []

    def test_lowercase_product_normalises(self):
        plugin = _plugin()
        resp = plugin.place_order(_request(product="nrml"))
        assert resp.ok
        assert plugin._session.kite_exec.placed[-1]["product"] == "NRML"


class TestDefaultProductsDeclaration:
    def test_derivative_segments_default_to_nrml(self):
        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        declared = dict(getattr(caps, "default_products", {}))
        assert declared, "kite must declare default_products"
        for seg in ("NFO", "BFO", "MCX", "CDS", "BCD"):
            assert declared[seg] == "NRML", seg
        for seg in ("NSE_EQ", "BSE_EQ"):
            assert declared[seg] == "CNC", seg

    def test_defaults_are_supported_products(self):
        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        for seg, prod in dict(getattr(caps, "default_products", {})).items():
            assert prod in caps.product_types, (seg, prod)


class TestFreezeQtyDeclaration:
    """S7 — index-derivative freeze quantities so the app's forced flattens
    split into exchange-legal child orders."""

    def test_index_freeze_quantities_declared(self):
        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        declared = dict(getattr(caps, "freeze_qty_by_underlying", {}))
        assert declared, "kite must declare freeze_qty_by_underlying"
        assert declared["NIFTY"] == 1800
        assert declared["BANKNIFTY"] == 900
        assert declared["SENSEX"] == 1000
        assert all(
            isinstance(v, int) and v > 0 for v in declared.values()
        )


class TestStrictOrderType:
    def test_unknown_order_type_rejects_not_market(self):
        # Review fix: "SL"/"STOP_MARKET" used to silently become an immediate
        # MARKET order — an unprotected fill instead of a resting stop.
        plugin = _plugin()
        for bad in ("SL", "STOP_MARKET", "TRAILING_STOP", ""):
            resp = plugin.place_order(_request(order_type=bad))
            assert not resp.ok, bad
            assert "unknown order type" in resp.error
        assert plugin._session.kite_exec.placed == []
