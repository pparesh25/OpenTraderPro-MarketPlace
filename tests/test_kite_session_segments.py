"""Session-window resolution for the segment codes symbol_master ACTUALLY stores.

The data half dumps derivative rows as ``{EXCH}-FUT`` / ``{EXCH}-OPT``
(``_dump_segment``), and those exact strings are what the app's square-off
services and router hours-gate pass to ``get_market_hours``. Pre-fix, every
such code fell through to the multi-venue fallback union whose LATEST close
(23:30/23:55 MCX non-agri) then anchored NFO/BFO/CDS/BCD force-flattens hours
after those markets closed — the orders could never fill and the positions
were left to the broker's penalty square-off / expiry settlement.

Both plugin halves are exec-loaded exactly as the host app loads them, and
both must agree per session boundary (exec gate consults the exec plugin,
data gate the data plugin).
"""
from __future__ import annotations

from datetime import time as dtime
from pathlib import Path

import pytest

pytest.importorskip("opentrader")  # app package required to exec-load the plugin

_PLUGINS = Path(__file__).resolve().parents[1] / "plugins"
EXEC = _PLUGINS / "exec" / "kite_broker_exec.txt"
DATA = _PLUGINS / "data" / "kite_broker_data.txt"


def _load_ns(path: Path) -> dict:
    ns: dict = {}
    exec(compile(path.read_text(), str(path), "exec"), ns)  # noqa: S102
    return ns


@pytest.fixture(scope="module")
def exec_ns() -> dict:
    return _load_ns(EXEC)


@pytest.fixture(scope="module")
def data_ns() -> dict:
    return _load_ns(DATA)


def _windows(ns: dict, plugin_cls: str, segment: str):
    return ns[plugin_cls].get_market_hours(None, segment)


# Every stored dump form + coarse form → its ONE session window's close.
# MCX non-agri close is date-aware (23:30 winter / 23:55 US-DST summer), so
# it is asserted against the plugin's own resolver rather than a literal.
_EQUITY_CLOSE = dtime(15, 30)
_CURRENCY_CLOSE = dtime(17, 0)
_EXPECTED_STATIC = {
    # cash + indices (indices dump as the bare exchange)
    "NSE_EQ": _EQUITY_CLOSE, "BSE_EQ": _EQUITY_CLOSE,
    "NSE": _EQUITY_CLOSE, "BSE": _EQUITY_CLOSE,
    # equity F&O — dump forms AND coarse forms
    "NFO-FUT": _EQUITY_CLOSE, "NFO-OPT": _EQUITY_CLOSE, "NFO": _EQUITY_CLOSE,
    "BFO-FUT": _EQUITY_CLOSE, "BFO-OPT": _EQUITY_CLOSE, "BFO": _EQUITY_CLOSE,
    # currency — dump forms AND coarse forms
    "CDS-FUT": _CURRENCY_CLOSE, "CDS-OPT": _CURRENCY_CLOSE, "CDS": _CURRENCY_CLOSE,
    "BCD-FUT": _CURRENCY_CLOSE, "BCD-OPT": _CURRENCY_CLOSE, "BCD": _CURRENCY_CLOSE,
    # MCX explicit agri sessions (stamped only via session_segment_for)
    "MCX_AGRI": dtime(21, 0), "MCX_AGRI_EARLY": dtime(17, 0),
    # case/whitespace robustness
    "nfo-fut": _EQUITY_CLOSE, " cds-opt ": _CURRENCY_CLOSE,
}


class TestDumpSegmentWindows:
    @pytest.mark.parametrize("plugin_cls,ns_name", [
        ("ExecPlugin", "exec_ns"), ("DataPlugin", "data_ns"),
    ])
    @pytest.mark.parametrize("segment,close", sorted(
        _EXPECTED_STATIC.items(), key=lambda kv: kv[0],
    ))
    def test_stored_segment_resolves_single_correct_window(
        self, plugin_cls, ns_name, segment, close, request,
    ):
        ns = request.getfixturevalue(ns_name)
        wins = _windows(ns, plugin_cls, segment)
        assert len(wins) == 1, (
            f"{plugin_cls}.get_market_hours({segment!r}) returned {len(wins)} "
            f"windows — a stored segment must resolve to exactly ONE session "
            f"(the multi-venue union mis-anchors square-offs)."
        )
        assert wins[0].close == close

    @pytest.mark.parametrize("plugin_cls,ns_name", [
        ("ExecPlugin", "exec_ns"), ("DataPlugin", "data_ns"),
    ])
    @pytest.mark.parametrize("segment", ["MCX-FUT", "MCX-OPT", "MCX"])
    def test_mcx_dump_segments_use_nonagri_close(
        self, plugin_cls, ns_name, segment, request,
    ):
        ns = request.getfixturevalue(ns_name)
        wins = _windows(ns, plugin_cls, segment)
        assert len(wins) == 1
        assert wins[0].close == ns["_mcx_nonagri_close_time"]()

    @pytest.mark.parametrize("plugin_cls,ns_name", [
        ("ExecPlugin", "exec_ns"), ("DataPlugin", "data_ns"),
    ])
    def test_empty_segment_keeps_union_fallback(
        self, plugin_cls, ns_name, request,
    ):
        # The engine refuses to anchor on an empty segment; the union stays
        # for broad callers (unchanged pre-existing behavior).
        ns = request.getfixturevalue(ns_name)
        assert len(_windows(ns, plugin_cls, "")) == 2

    def test_exec_and_data_agree_on_every_stored_code(self, exec_ns, data_ns):
        codes = [
            "NSE_EQ", "BSE_EQ", "NSE", "BSE",
            "NFO-FUT", "NFO-OPT", "BFO-FUT", "BFO-OPT",
            "CDS-FUT", "CDS-OPT", "BCD-FUT", "BCD-OPT",
            "MCX-FUT", "MCX-OPT", "MCX_AGRI", "MCX_AGRI_EARLY",
        ]
        for code in codes:
            e = [(w.open, w.close) for w in _windows(exec_ns, "ExecPlugin", code)]
            d = [(w.open, w.close) for w in _windows(data_ns, "DataPlugin", code)]
            assert e == d, f"exec/data session windows diverge for {code}: {e} vs {d}"


class TestSessionSegmentForHook:
    """MCX agri instruments share the MCX-FUT/-OPT dump segments; the hook
    splits them out by sector + underlying root so square-offs anchor to the
    21:00 / 17:00 agri closes instead of 23:30/23:55."""

    def _hook(self, exec_ns):
        return lambda *a, **kw: exec_ns["ExecPlugin"].session_segment_for(
            None, *a, **kw,
        )

    def test_non_mcx_collapses_dump_suffix(self, exec_ns):
        hook = self._hook(exec_ns)
        assert hook("NFO-OPT") == "NFO"
        assert hook("CDS-FUT", sector=None, underlying=None) == "CDS"
        assert hook("NSE_EQ") == "NSE_EQ"

    def test_mcx_nonagri_sectors_stay_mcx(self, exec_ns):
        hook = self._hook(exec_ns)
        for sector, root in [
            ("Bullion", "GOLD"), ("Energy", "CRUDEOIL"),
            ("Base Metals", "COPPER"), ("Index", "MCXMETLDEX"),
            (None, "GOLD"), ("Other", "NEWTHING"),
        ]:
            assert hook("MCX-FUT", sector=sector, underlying=root) == "MCX"

    def test_mcx_agri_roots_split_sessions(self, exec_ns):
        hook = self._hook(exec_ns)
        # 21:00 session (internationally referenceable agri)
        for root in ("COTTON", "COTTONREF", "KAPAS", "COTTONOIL"):
            assert hook("MCX-FUT", sector="Agri-Commodity", underlying=root) \
                == "MCX_AGRI", root
        # 17:00 session
        for root in ("CARDAMOM", "MENTHAOIL", "CASTORSEED", "CASTOR"):
            assert hook("MCX-OPT", sector="Agri-Commodity", underlying=root) \
                == "MCX_AGRI_EARLY", root

    def test_unknown_agri_root_fails_to_earliest_close(self, exec_ns):
        # Unknown agri root → earliest close (fail-early is the safe
        # direction for a forced flatten).
        hook = self._hook(exec_ns)
        assert hook("MCX-FUT", sector="Agri-Commodity", underlying="NEWAGRI") \
            == "MCX_AGRI_EARLY"
        assert hook("MCX-FUT", sector="Agri-Commodity", underlying=None) \
            == "MCX_AGRI_EARLY"

    def test_explicit_agri_segments_pass_through(self, exec_ns):
        hook = self._hook(exec_ns)
        assert hook("MCX_AGRI") == "MCX_AGRI"
        assert hook("MCX_AGRI_EARLY", sector="Agri-Commodity") == "MCX_AGRI_EARLY"

    def test_hook_windows_are_the_agri_closes(self, exec_ns):
        seg = exec_ns["ExecPlugin"].session_segment_for(
            None, "MCX-FUT", sector="Agri-Commodity", underlying="COTTON",
        )
        wins = exec_ns["ExecPlugin"].get_market_hours(None, seg)
        assert [w.close for w in wins] == [dtime(21, 0)]


class TestIntradayCutoffDeclaration:
    """S3 — Zerodha's RMS square-off cutoffs (minutes before close) must be
    declared per segment so the app's intraday flatten beats the broker's
    penalty square-off; fresh MIS orders are REJECTED past the cutoff."""

    def test_cutoffs_declared_conservatively(self, exec_ns):
        caps = exec_ns["ExecPlugin"].CAPABILITIES
        cutoffs = dict(getattr(caps, "intraday_squareoff_cutoff_minutes", {}))
        assert cutoffs, "kite must declare intraday_squareoff_cutoff_minutes"
        # Conservative (largest historically published) figures — see the
        # declaration comment. Equity 15:20 / F&O 15:25 / CDS 16:45 / MCX −25.
        assert cutoffs["NSE_EQ"] == 10 and cutoffs["BSE_EQ"] == 10
        assert cutoffs["NFO"] == 5 and cutoffs["BFO"] == 5
        assert cutoffs["CDS"] == 15 and cutoffs["BCD"] == 15
        assert cutoffs["MCX"] == 25

    def test_cutoff_keys_are_declared_segments(self, exec_ns):
        caps = exec_ns["ExecPlugin"].CAPABILITIES
        cutoffs = dict(getattr(caps, "intraday_squareoff_cutoff_minutes", {}))
        assert set(cutoffs).issubset(set(caps.segments))

    def test_deadline_precedes_each_session_close(self, exec_ns):
        # Sanity: deadline (close − cutoff) must land INSIDE the session for
        # every declared segment, else the window could never fire.
        from datetime import datetime, timedelta
        plugin_cls = exec_ns["ExecPlugin"]
        caps = plugin_cls.CAPABILITIES
        cutoffs = dict(getattr(caps, "intraday_squareoff_cutoff_minutes", {}))
        for seg, minutes in cutoffs.items():
            wins = plugin_cls.get_market_hours(None, seg)
            assert len(wins) == 1, seg
            close = wins[0].close
            open_ = wins[0].open
            deadline = (
                datetime(2024, 1, 25, close.hour, close.minute)
                - timedelta(minutes=minutes)
            ).time()
            assert open_ < deadline < close, (seg, deadline)


class TestExpiryLifecycleHooks:
    """S4 — expiring-contract close (CDS/BCD 12:30) + physical-delivery
    advance days (MCX tender rule: Zerodha closes ~8 days before expiry)."""

    def test_currency_expiring_contracts_stop_at_1230(self, exec_ns):
        cls = exec_ns["ExecPlugin"]
        from datetime import time as dtime
        for seg in ("CDS", "BCD", "CDS-FUT", "CDS-OPT", "BCD-OPT"):
            assert cls.expiring_contract_close(None, seg) == dtime(12, 30), seg
        for seg in ("NFO", "NFO-OPT", "MCX", "MCX-FUT", "NSE_EQ"):
            assert cls.expiring_contract_close(None, seg) is None, seg

    def test_mcx_physical_sectors_declare_8_day_advance(self, exec_ns):
        cls = exec_ns["ExecPlugin"]
        for sector in ("Bullion", "Base Metals", "Agri-Commodity"):
            assert cls.expiry_close_advance_days(
                None, "MCX-FUT", sector=sector, underlying="X",
            ) == 8, sector

    def test_cash_settled_and_non_mcx_stay_on_expiry_day(self, exec_ns):
        cls = exec_ns["ExecPlugin"]
        assert cls.expiry_close_advance_days(
            None, "MCX-FUT", sector="Energy", underlying="CRUDEOIL",
        ) == 0
        assert cls.expiry_close_advance_days(
            None, "MCX-OPT", sector="Index", underlying="MCXBULLDEX",
        ) == 0
        assert cls.expiry_close_advance_days(
            None, "NFO-FUT", sector=None, underlying="NIFTY",
        ) == 0
        assert cls.expiry_close_advance_days(None, "CDS-FUT") == 0


class TestCrossHalfConsistency:
    """Review fixes: the exec half's per-underlying/root declarations only
    fire when the DATA half actually stamps the matching stored values —
    these seams shipped dead once, so they are pinned across the two files."""

    def test_freeze_map_covers_the_stored_alias_forms(self, exec_ns, data_ns):
        # The data half aliases NSE index roots at dump time (NIFTY →
        # "NIFTY 50"); the square-off services pass the STORED form, so the
        # freeze map must key it too or the split never fires.
        freeze = dict(
            exec_ns["ExecPlugin"].CAPABILITIES.freeze_qty_by_underlying,
        )
        alias = dict(data_ns["_INDEX_UNDERLYING_ALIAS"])
        for root, stored in alias.items():
            if root in freeze:
                assert stored in freeze, (
                    f"freeze map has root {root!r} but not the stored alias "
                    f"{stored!r} — the split would never fire in production"
                )
                assert freeze[stored] == freeze[root]

    def test_agri_late_roots_are_sector_mapped_in_the_data_half(
        self, exec_ns, data_ns,
    ):
        # session_segment_for gates on sector == "Agri-Commodity" BEFORE the
        # root set is consulted; a late-root missing from _MCX_SECTORS gets
        # sector "Other" and the agri split + tender advance are dead for it.
        sectors = dict(data_ns["_MCX_SECTORS"])
        for root in exec_ns["_MCX_AGRI_LATE_ROOTS"]:
            assert sectors.get(root) == "Agri-Commodity", (
                f"{root!r} in _MCX_AGRI_LATE_ROOTS but not sector-mapped "
                f"Agri-Commodity in the data half — the split never fires"
            )

    def test_key_agri_contracts_are_agri_sector(self, data_ns):
        sectors = dict(data_ns["_MCX_SECTORS"])
        for root in ("CPO", "COTTONCNDY", "CASTOR", "CASTORSEED",
                     "MENTHAOIL", "CARDAMOM"):
            assert sectors.get(root) == "Agri-Commodity", root
