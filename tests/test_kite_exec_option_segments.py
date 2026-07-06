"""The Kite exec half must advertise every derivative exchange Zerodha
order-routes (NFO, BFO, MCX, CDS, BCD) in ``CAPABILITIES.segments``.

``place_order`` passes ``request.exchange`` straight through to the Kite API,
so all five are genuinely tradable. The app's Quick-Order instrument-type gate
treats ``caps.segments`` as the source of truth for whether an OPTION is
orderable — so omitting BFO (BSE F&O) / BCD (BSE currency) there silently
refused options Zerodha actually trades. We exec-load the shipped ``.txt``
exactly as the host does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("opentrader")  # app package required to exec-load the plugin

EXEC = (
    Path(__file__).resolve().parents[1]
    / "plugins" / "exec" / "kite_broker_exec.txt"
)

# Every Zerodha exchange that lists options + the two cash segments.
_DERIVATIVE_EXCHANGES = ("NFO", "BFO", "MCX", "CDS", "BCD")
_CASH_SEGMENTS = ("NSE_EQ", "BSE_EQ")


def _load_ns() -> dict:
    ns: dict = {}
    exec(compile(EXEC.read_text(), str(EXEC), "exec"), ns)  # noqa: S102
    return ns


class TestKiteExecOptionSegments:
    def test_caps_advertise_all_derivative_exchanges(self):
        ns = _load_ns()
        segments = ns["ExecPlugin"].CAPABILITIES.segments
        for exch in _DERIVATIVE_EXCHANGES:
            assert exch in segments, (
                f"{exch} missing from kite exec caps.segments — the Quick-Order "
                f"gate would refuse {exch} options Zerodha trades. Got {segments!r}"
            )

    def test_caps_still_advertise_cash_segments(self):
        # Regression: the BFO/BCD addition must not drop the cash segments.
        ns = _load_ns()
        segments = ns["ExecPlugin"].CAPABILITIES.segments
        for seg in _CASH_SEGMENTS:
            assert seg in segments, f"{seg} missing from {segments!r}"

    def test_exec_derivative_set_matches_data_half(self):
        # The exec half must cover the same derivative exchanges the data half
        # declares (kite_broker_data._DERIVATIVE_EXCHANGES) so a symbol the
        # builder can catalogue is also orderable.
        ns = _load_ns()
        data = (
            EXEC.parent.parent / "data" / "kite_broker_data.txt"
        ).read_text()
        # Cheap, dependency-free assertion: the data half names the same five.
        for exch in _DERIVATIVE_EXCHANGES:
            assert f'"{exch}"' in data, f"{exch} not referenced in kite_broker_data"
        segments = ns["ExecPlugin"].CAPABILITIES.segments
        assert set(_DERIVATIVE_EXCHANGES).issubset(set(segments))


class TestKiteShortProducts:
    """v3-P5c-live-g / D4 — the exec half declares which product a sell-to-open
    may use per segment, so the router can auto-assign a short-capable product.
    Without this every ENTRY_SHORT on Zerodha is rejected (fail-safe)."""

    def _caps(self):
        return _load_ns()["ExecPlugin"].CAPABILITIES

    def test_short_products_declared(self):
        sp = dict(getattr(self._caps(), "short_products", {}))
        assert sp, "kite exec must declare short_products or live shorts are inert"

    def test_equity_short_is_intraday_only_never_cnc(self):
        # The load-bearing safety invariant: an equity short auto-assigns MIS,
        # NEVER CNC — a delivery short needs stock-borrow/SLB (not modelled).
        sp = self._caps().short_products
        for seg in ("NSE_EQ", "BSE_EQ"):
            assert sp[seg] == ("MIS",), f"{seg} equity short must be MIS-only, got {sp[seg]!r}"
            assert "CNC" not in sp[seg]

    def test_fno_short_defaults_to_nrml(self):
        # Derivatives are two-sided; NRML (carry) is the [0] auto-assign default,
        # MIS also allowed.
        sp = self._caps().short_products
        for seg in ("NFO", "BFO", "MCX", "CDS", "BCD"):
            assert sp[seg][0] == "NRML", f"{seg} short default should be NRML, got {sp[seg]!r}"
            assert set(sp[seg]) == {"NRML", "MIS"}

    def test_short_segments_are_all_tradable(self):
        # Every segment with a short product must be an advertised, orderable
        # segment (else the short would resolve a product for an un-routable seg).
        caps = self._caps()
        assert set(caps.short_products).issubset(set(caps.segments))

    def test_short_products_subset_of_product_types(self):
        # Every short-capable product must be a product the plugin actually
        # supports (MIS/NRML are in product_types; a typo'd product would be
        # advertised as short-capable but rejected at place_order).
        caps = self._caps()
        for seg, prods in caps.short_products.items():
            for p in prods:
                assert p in caps.product_types, (
                    f"{seg} short product {p!r} not in product_types {caps.product_types!r}"
                )
