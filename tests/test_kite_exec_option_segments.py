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
