# OpenTraderPro MarketPlace

Official marketplace of dynamically loadable text-file extensions for the [OpenTrader-Pro](https://github.com/pparesh25) desktop trading app.

This repository ships **plugins** (broker connectors), **strategies** (signal logic), and **indicators** (charting overlays) as plain `.txt` files. The OpenTrader-Pro app loads each one at runtime via its `TextFileLoader` infrastructure — no recompile, no Python package install.

---

## ⚠️ Read SECURITY.md before installing

Every file in this repository is **executable Python code** that the OpenTrader-Pro app runs with full user privileges. Treat each install with the same caution as installing any third-party software. See [SECURITY.md](SECURITY.md) for the threat model and the upcoming integrity-verification roadmap.

---

## What's in this repository

```
OpenTraderPro_MarketPlace/
├── LICENSE                   GNU General Public License v3.0
├── README.md                 (this file)
├── SECURITY.md               Threat model + integrity roadmap
├── plugins/
│   ├── data/                 Market-data plugins (DataPluginV2)
│   │   ├── openbb_data.txt
│   │   ├── kite_broker_data.txt
│   │   └── crypto_exchange_data.txt
│   └── exec/                 Order-execution plugins (ExecPluginV2)
│       ├── kite_broker_exec.txt
│       └── crypto_exchange_exec.txt
├── strategies/               Signal/strategy logic (StrategyBase)
│   ├── delivery_exit.txt
│   ├── adx_ema_intraday.txt
│   └── mis_exit_all.txt
└── indicators/               Custom charting overlays (BaseIndicator)
    ├── averages/             SMA, EMA, DEMA, TEMA, WMA, VWAP, Parabolic SAR
    ├── bands/                Bollinger, Keltner, Ichimoku
    └── oscillators/          RSI, MACD, Stochastic, ADX, Aroon, ATR, CCI, MFI, OBV, Williams %R
```

---

## Quick install

The OpenTrader-Pro app reads from these user-home directories on startup:

| Type | App-home directory |
|---|---|
| Data plugins | `~/.opentrader-pro/plugins/data/` |
| Exec plugins | `~/.opentrader-pro/plugins/exec/` |
| Strategies | `~/.opentrader-pro/strategies/` |
| Indicators | `~/.opentrader-pro/indicators/{averages,bands,oscillators,custom}/` |

Mirror the repo path → app-home path for each file you want:

```bash
# Example: install Zerodha (kite_broker) plugin
cp plugins/data/kite_broker_data.txt ~/.opentrader-pro/plugins/data/
cp plugins/exec/kite_broker_exec.txt ~/.opentrader-pro/plugins/exec/

# Example: install a strategy
cp strategies/delivery_exit.txt ~/.opentrader-pro/strategies/

# Example: install the VWAP indicator
cp indicators/averages/vwap.txt ~/.opentrader-pro/indicators/averages/
```

After copying, restart the app. Plugins prompt a one-time consent dialog; strategies and indicators load directly (a consent gate for them is planned — see SECURITY.md).

The Accounts panel "Get example plugins" button will eventually open this repository in your browser; an in-app downloader is on the roadmap.

---

## Available extensions

### Plugins

| Plugin | Type | Coverage | Notes |
|---|---|---|---|
| `openbb_data` | data | Multi-provider data via OpenBB platform | No order execution; data-only |
| `kite_broker_data` | data | NSE / BSE / NFO / MCX / CDS via Kite Connect | Indian markets — equity + F&O + commodity |
| `kite_broker_exec` | exec | Same | Daily-OAuth (06:00 IST token expiry) + SEBI static-IP routing |
| `crypto_exchange_data` | data | Binance spot + USD-M + COIN-M futures | Real-time tickers + historical klines |
| `crypto_exchange_exec` | exec | Same | Per-call SOCKS5 proxy routing + V3 §F7 user-data WebSocket worker |

`kite_broker` and `crypto_exchange` ship as a data + exec pair sharing one session per alias via the app's `session_registry` primitive — install both files for the same broker if you want OAuth/auth to happen once across data + execution.

### Strategies

| Strategy | One-line summary |
|---|---|
| `delivery_exit` | CNC carry-forward exit logic |
| `adx_ema_intraday` | ADX + EMA crossover for intraday signals |
| `mis_exit_all` | MIS square-off-all-positions before market close |

### Indicators

| Indicator | Category | One-line summary |
|---|---|---|
| `sma` | averages | Simple moving average |
| `ema` | averages | Exponential moving average |
| `dema` | averages | Double exponential moving average |
| `tema` | averages | Triple exponential moving average |
| `wma` | averages | Weighted moving average |
| `vwap` | averages | Volume-weighted average price (intraday session-anchored) |
| `parabolic_sar` | averages | Parabolic Stop-and-Reverse trailing stop |
| `bollinger` | bands | Bollinger Bands (SMA ± k·σ) |
| `keltner` | bands | Keltner Channels (EMA ± k·ATR) |
| `ichimoku` | bands | Ichimoku Cloud (5-line equilibrium chart) |
| `rsi` | oscillators | Relative Strength Index |
| `macd` | oscillators | Moving Average Convergence/Divergence |
| `stochastic` | oscillators | Stochastic Oscillator (%K + %D) |
| `adx` | oscillators | Average Directional Index (trend strength) |
| `aroon` | oscillators | Aroon Up/Down (trend identification) |
| `atr` | oscillators | Average True Range (volatility) |
| `cci` | oscillators | Commodity Channel Index |
| `mfi` | oscillators | Money Flow Index (volume-weighted RSI) |
| `obv` | oscillators | On-Balance Volume |
| `williams_r` | oscillators | Williams %R (momentum) |

---

## Authoring your own

To author a new plugin / strategy / indicator, start from the auto-seeded template in your app-home folder:

| Type | Template file (auto-seeded on first app run) |
|---|---|
| Data plugin | `~/.opentrader-pro/plugins/data/_template_data.txt` |
| Exec plugin | `~/.opentrader-pro/plugins/exec/_template_exec.txt` |
| Strategy | `~/.opentrader-pro/strategies/_template.txt` |
| Indicator | `~/.opentrader-pro/indicators/custom/_template.txt` |

Plugins additionally have a CLI validator:

```bash
python -m opentrader.connectors_v2.validate /path/to/your_plugin.txt
```

A validator for strategies and indicators is on the roadmap. See the OpenTrader-Pro docs (`docs/architecture/plugin_authoring_guide.md`) for the plugin contract surface.

---

## Contributing

Pull requests are welcome. Keep these in mind:

- Every new file must be reviewable plain Python — no embedded binaries, no obfuscation, no network-fetched code at import time.
- Folder convention is enforced by the app loader. Place files under the matching `plugins/{data,exec}/` / `strategies/` / `indicators/{category}/` path.
- Keep the file self-contained — the loader `exec()`s each file in an isolated namespace; any helper class or function the file needs must live inside it.
- For broker-shared sessions, route through `opentrader.connectors_v2.session_registry.get_or_create_session(namespace=…, alias=…, factory=…)` so a data + exec pair shares one session.
- Add the file to the appropriate table in this README.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

These files are example/reference plugins distributed under GPL-3.0. You are free to fork, modify, and redistribute under the same license. Forks are encouraged — if you build something useful, send a pull request.

---

## Roadmap

- **In-app downloader** (Phase M3 in main app): "Get example plugins" button currently opens this repo in a browser; a future release will fetch + install in-app.
- **Cryptographic signing** (Phase M1): each `.txt` will ship with an Ed25519 `.sig` sibling file; the app will verify signatures at load time so a tampered file refuses to load.
- **Trusted-only mode** (Phase M2): a Settings toggle defaults to "marketplace files only"; user-authored files require explicit opt-in (developer mode).
- **Consent gate for strategies + indicators** (Phase S3): close the existing security gap where strategies/indicators in `~/.opentrader-pro/{strategies,indicators}/` load with no user confirmation. Plugins have this gate since V3 R1.
- **Authoring guides**: dedicated `strategy_authoring_guide.md` + `indicator_authoring_guide.md` (plugins already have one).

The roadmap is tracked in the main app repository.

---

## Links

- Main app: <https://github.com/pparesh25> (OpenTrader-Pro repository)
- Issues / questions: open a GitHub issue against this repository
- License: [GPL-3.0](LICENSE)
