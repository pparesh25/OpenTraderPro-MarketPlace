"""💰 S4 — Binance quantities must survive the plugin boundary as floats.

The app's journal columns have been DOUBLE since F-S7-7 (schema v7) and
``OrderRequest.quantity`` has been ``float`` since F-S6-G. The precision was
being destroyed one layer earlier, inside this plugin: four ``int()`` casts on
the read path turned every fractional Binance quantity into a whole number, or
into zero, before the app ever saw it.

Consequences each cast had, in the app:

* ``_order_to_record`` — ``executedQty`` is what ``OrderTracker`` journals as
  ``filled_quantity``. A 0.5 BTC fill was recorded as 0, so the trade journal
  and every position derived from it were silently wrong.
* spot ``get_positions`` — ``int(total) if total >= 1 else 0`` reported 61.38
  AVAX as 61 and any sub-unit holding as a flat 0, so the app closed positions
  the user still held.
* futures ``get_positions`` — ``positionAmt`` is fractional on every contract.

The plugin could always *place* fractional orders — ``place_order`` rounds
through ``round_quantity``, which reads the symbol's real LOT_SIZE filter — but
``ExecCapabilities.supports_fractional_quantity`` defaulted to False, so the
app treated Binance as a whole-share venue.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentrader")

EXEC = (
    Path(__file__).resolve().parents[1]
    / "plugins" / "exec" / "crypto_exchange_exec.txt"
)


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(EXEC.read_text(), str(EXEC), "exec"), ns)  # noqa: S102
    return ns


class TestCapabilitiesDeclareFractional:
    def test_the_plugin_advertises_fractional_support(self):
        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        assert caps.supports_fractional_quantity is True, (
            "undeclared, the app gates the Quick Order spin box to whole "
            "numbers, a paper-wrapped Binance account rejects fractional "
            "orders, and PositionSizer floors crypto sizing to whole coins"
        )

    def test_the_fallback_step_does_not_floor_real_crypto_sizes(self):
        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        assert 0 < caps.default_step_size <= 1e-8, (
            "this is the fallback used whenever the per-symbol step cache "
            "misses; anything coarser floors legitimate sizes to zero"
        )

    def test_the_fallback_step_accepts_binance_precision_quantities(self):
        """The declared step feeds ``validate_order_quantity``'s alignment
        check on the paper path. It must accept every quantity Binance would
        — 8 decimal places is the exchange's finest increment."""
        from opentrader.contexts.execution.domain.order_validation import (
            validate_order_quantity,
        )
        from opentrader.kernel.orders import OrderRequest

        caps = _load_ns()["ExecPlugin"].CAPABILITIES
        for qty in (0.5, 1.7, 0.001, 0.00012345, 61.38, 0.00000001):
            request = OrderRequest(
                account_id="binance::acct", symbol="BTCUSDT",
                exchange="BINANCE", segment="CRYPTO_SPOT", side="BUY",
                quantity=qty, order_type="MARKET", product="SPOT",
            )
            assert validate_order_quantity(request, caps) is None, (
                f"{qty} is a valid Binance quantity and must not be rejected"
            )


class TestOrderRecordKeepsFractionalFills:
    """``_order_to_record`` is the read path OrderTracker journals from."""

    def _record(self, ns, **over):
        payload = {
            "orderId": 42, "symbol": "BTCUSDT", "side": "BUY",
            "origQty": "0.5", "executedQty": "0.25",
            "type": "LIMIT", "status": "PARTIALLY_FILLED",
            "price": "100000.0", "time": 1_700_000_000_000,
        }
        payload.update(over)
        return ns["_order_to_record"](payload, ns["SPOT"])

    def test_a_fractional_fill_is_not_truncated(self):
        ns = _load_ns()
        rec = self._record(ns)
        assert rec.quantity == pytest.approx(0.5)
        assert rec.filled_quantity == pytest.approx(0.25), (
            "pre-fix int(0.25) == 0 — the journal recorded a filled order "
            "as unfilled"
        )

    def test_a_sub_unit_order_does_not_collapse_to_zero(self):
        ns = _load_ns()
        rec = self._record(ns, origQty="0.001", executedQty="0.001")
        assert rec.quantity == pytest.approx(0.001)
        assert rec.filled_quantity == pytest.approx(0.001)

    def test_whole_quantities_are_unchanged(self):
        """Equity-shaped values must read back exactly as before."""
        ns = _load_ns()
        rec = self._record(ns, origQty="10", executedQty="10")
        assert rec.quantity == 10
        assert rec.filled_quantity == 10


class _Resp:
    """Minimal stand-in for the authenticated session's client."""

    def __init__(self, balances=None, positions=None):
        self._balances = balances or []
        self._positions = positions or []

    def get_account(self):
        return {"balances": self._balances}


class TestSpotHoldingsKeepTheirDecimals:
    def _positions_for(self, ns, balances):
        ExecPlugin = ns["ExecPlugin"]
        plugin = object.__new__(ExecPlugin)
        plugin.alias = "acct"

        class _Session:
            is_authenticated = True
            client = _Resp(balances=balances)
            api_lock = __import__("threading").Lock()
            _segment_perm_denied = None

            def _signed_call_proxy(self):
                import contextlib
                return contextlib.nullcontext()

            def load_symbols(self, segment):
                return None

        plugin._session = _Session()
        return plugin.get_positions()

    def test_a_fractional_balance_is_reported_in_full(self):
        ns = _load_ns()
        positions = self._positions_for(
            ns, [{"asset": "AVAX", "free": "61.38", "locked": "0"}]
        )
        avax = [p for p in positions if p.symbol == "AVAX"]
        assert avax and avax[0].quantity == pytest.approx(61.38), (
            "pre-fix int(61.38) == 61 — 0.38 AVAX vanished from the journal"
        )

    def test_a_sub_unit_balance_is_not_reported_as_flat(self):
        """``int(total) if total >= 1 else 0`` turned a real holding into a
        zero-quantity row, and the app closed the position out."""
        ns = _load_ns()
        positions = self._positions_for(
            ns, [{"asset": "FIL", "free": "0.4", "locked": "0"}]
        )
        fil = [p for p in positions if p.symbol == "FIL"]
        assert fil, "a 0.4 FIL holding must be reported at all"
        assert fil[0].quantity == pytest.approx(0.4)
