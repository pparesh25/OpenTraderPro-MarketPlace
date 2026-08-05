# OpenTraderPro MarketPlace

Official marketplace of dynamically loadable text-file extensions for the [OpenTrader-Pro](https://github.com/pparesh25) desktop trading app.

This repository ships **plugins** (broker connectors), **strategies** (signal logic), and **indicators** (charting overlays) as plain `.txt` files. The OpenTrader-Pro app loads each one at runtime via its `TextFileLoader` infrastructure — no recompile, no Python package install.

---

## ⚠️ Read SECURITY.md before installing

Every file in this repository is **executable Python code** that the OpenTrader-Pro app runs with full user privileges. Treat each install with the same caution as installing any third-party software. See [SECURITY.md](SECURITY.md) for the full threat model and verification details.

---

## Philosophy

The marketplace is built around three principles. Read these before you install anything.

### 1. Source-readable is the primary defence

Every `.txt` file in this repository is **plain Python source**. No binaries, no obfuscation, no minification, no network-fetched code at import time. You can open any file in a text editor and read exactly what it does before installing it. This is the contract — opaqueness is incompatible with the marketplace.

### 2. Cryptographic signing is *defence-in-depth*, not a substitute for review

The marketplace ships **Ed25519 signatures** for every file (Phase M1, done 2026-04-28). The OpenTrader Pro app verifies each signature against an embedded public key before loading the file, and a GitHub Action verifies signatures on every commit + PR. The cryptography is properly set up, end-to-end tested, and working in production today.

**However** — signing only proves that **the maintainer** signed the file. It does NOT prove the maintainer's code is benign, nor that the maintainer's intent matches yours. A signed file from a compromised maintainer key would still verify; a signed file written carelessly would still verify.

> **Cryptographic verification is an additional precaution taken by the developer to defend against tampering between this repo and your disk. It is NOT a substitute for you reading the code.**

### 3. Reviewing downloaded files is *your* responsibility too

Trading code talks to your broker, places real-money orders, and reads your secrets. The marketplace ships small, single-purpose, plain-Python files specifically so you *can* read them — typically a few hundred lines each. Open every plugin / strategy / indicator before installing and confirm:

- It does what its README claims it does.
- It only talks to the brokers + endpoints you expect.
- It doesn't read or write paths outside its own scope.
- Its dependencies are libraries you already trust.

If you can't read Python comfortably, ask someone who can — or stick to reading [SECURITY.md](SECURITY.md) and accepting the trust-the-maintainer trade-off explicitly. Either is a valid choice. Installing without reading and *assuming* the signature makes it safe is not.

---

## What's in this repository

```
OpenTraderPro-MarketPlace/
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

## Where downloaded files live on your system

The OpenTrader Pro app uses **two separate directories** for marketplace content vs. files you author yourself. The split is deliberate — it lets the app load the verified marketplace by default and isolate your own work behind an explicit toggle.

| Directory | Purpose | Loaded by default? |
|---|---|---|
| `~/.opentrader-pro/marketplace_cache/` | Files installed by the in-app marketplace installer. Every file is signed and verified at load. Files are written read-only (`chmod 0o444`) on POSIX. | ✅ Always |
| `~/.opentrader-pro/plugins/`, `strategies/`, `indicators/` | Files you authored, sideloaded, or copied manually. Unsigned files load with a WARNING; signed-but-tampered files load with a CRITICAL warning. | ❌ Only when **Developer Mode** is on |

Inside each root, the layout mirrors this repository:

```
~/.opentrader-pro/marketplace_cache/
├── plugins/
│   ├── data/        ← copied from this repo's plugins/data/
│   └── exec/        ← copied from this repo's plugins/exec/
├── strategies/      ← copied from this repo's strategies/
└── indicators/
    ├── averages/    ← copied from this repo's indicators/averages/
    ├── bands/
    ├── oscillators/
    └── custom/
```

The user-edit roots (`~/.opentrader-pro/{plugins,strategies,indicators}/`) follow the same shape but are seeded with `_template.txt` examples on first launch instead of marketplace content.

---

## Install — preferred path: in-app installer (Phase M3)

The OpenTrader Pro app ships an in-app installer as of 2026-04-28 (V3 §M3). This is the recommended way to consume the marketplace.

**Inside the app:** open the **Accounts** panel → click **"Install marketplace files"**.

The installer fetches the latest marketplace zip from GitHub, verifies every `.txt` against its embedded `.sig` using the embedded public key, rejects unsigned / tampered / mis-located entries, and installs the verified files into `~/.opentrader-pro/marketplace_cache/` read-only. A "Browse on GitHub →" companion button opens this repo so you can review before installing.

Headless / scripted equivalent:

```bash
python -m opentrader.connectors_v2.marketplace_install
# or against a local clone of this repo:
python -m opentrader.connectors_v2.marketplace_install --source /path/to/clone
```

After install, restart the app. Plugins prompt a one-time consent dialog (V3 R1); strategies and indicators have an analogous consent gate (V3 §S3) — both default to off until you click "Allow".

---

## Install — fallback: manual copy

If the in-app installer is unavailable (offline machine, custom directory layout, you want to inspect every file before copying), fall through to manual `cp`:

```bash
git clone https://github.com/pparesh25/OpenTraderPro-MarketPlace
cd OpenTraderPro-MarketPlace

# Verify signatures locally before copying — see SECURITY.md
pip install cryptography
python .github/scripts/verify_signatures.py
# Expected: "33 verified, 0 failed"

# Then copy whatever you want into the marketplace_cache:
cp plugins/data/kite_broker_data.txt   ~/.opentrader-pro/marketplace_cache/plugins/data/
cp plugins/data/kite_broker_data.txt.sig ~/.opentrader-pro/marketplace_cache/plugins/data/
cp plugins/exec/kite_broker_exec.txt   ~/.opentrader-pro/marketplace_cache/plugins/exec/
cp plugins/exec/kite_broker_exec.txt.sig ~/.opentrader-pro/marketplace_cache/plugins/exec/

cp strategies/delivery_exit.txt        ~/.opentrader-pro/marketplace_cache/strategies/
cp strategies/delivery_exit.txt.sig    ~/.opentrader-pro/marketplace_cache/strategies/

cp indicators/averages/vwap.txt        ~/.opentrader-pro/marketplace_cache/indicators/averages/
cp indicators/averages/vwap.txt.sig    ~/.opentrader-pro/marketplace_cache/indicators/averages/
```

**Always copy the `.sig` sibling alongside the `.txt`.** Without the signature the file refuses to load from the marketplace cache. (User-edit dirs accept unsigned files in Developer Mode.)

### Line endings — why this repository ships `.gitattributes`

Signatures are taken over each file's **raw bytes**, so anything that rewrites those bytes invalidates them — including an end-of-line conversion. Git's default on Windows is `core.autocrlf=true`, which rewrites LF to CRLF on checkout, and until `.gitattributes` existed a normal `git clone` on Windows produced a working tree where **all 33 signatures failed**. The app reported every plugin, strategy and indicator as *tampered* and installed nothing. Nothing had been tampered with; the checkout had rewritten the files.

`.gitattributes` now marks the tree `-text`, so git copies those bytes verbatim in both directions. **You do not need to do anything special** — `git clone` is enough, on any platform.

Two things worth knowing anyway:

- If you are on a clone taken **before** this landed, re-clone it — the old working tree still holds the rewritten bytes.
- If verification fails on *every* file at once, suspect the checkout rather than the signatures: `verify_signatures.py` will say `0 verified, 33 failed`, and re-cloning is the quickest way to confirm that is all it was.

A failure on only *some* files is a different story, and does mean those files and their signatures disagree — read [SECURITY.md](SECURITY.md).

---

## Developer Mode

**Off by default.** Developer Mode is a Settings toggle (V3 §M2, done 2026-04-28) that controls whether the app loads files from the user-edit dirs (`~/.opentrader-pro/plugins/`, `strategies/`, `indicators/`).

| State | Loads `marketplace_cache/`? | Loads `~/.opentrader-pro/{plugins,strategies,indicators}/`? |
|---|---|---|
| **OFF** (default) | ✅ Yes — verified signatures only | ❌ Skipped entirely |
| **ON** (developer) | ✅ Yes | ✅ Yes — unsigned files load with WARNING |

### When to enable Developer Mode

- You're authoring your own plugin / strategy / indicator from a `_template.txt`.
- You've forked this marketplace + have local edits you want to test before submitting a PR.
- You're sideloading a plugin from a third party that is NOT in this marketplace (you've reviewed the source yourself and accepted the risk).

### When NOT to enable it

- You only want to use the official marketplace files. Leaving Developer Mode OFF guarantees the app cannot load anything you didn't explicitly install via the verified installer.
- You're handing the laptop to someone less technical. Developer Mode raises the surface area of "what code can run inside the app" — keep it off if you're not the only person at the keyboard.

### Where to find it

Settings → **Marketplace** tab → "Allow custom plugins / strategies / indicators (developer mode)".

The app remembers your choice. The toggle is sticky — first-boot smart-default reads from disk state (existing user files → ON, empty → OFF) so existing users aren't surprised.

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

All three extension types ship a CLI validator. Run before dropping a new file into your `~/.opentrader-pro/` directory so syntax errors, missing abstract methods, and metadata typos surface in a one-shot terminal command instead of silently as a half-loaded extension at app boot:

```bash
# Plugins (V3 §P3)
python -m opentrader.connectors_v2.validate /path/to/your_plugin.txt

# Strategies (Phase S2)
python -m opentrader.strategy.validate /path/to/your_strategy.txt

# Indicators (Phase S2)
python -m opentrader.indicators.validate /path/to/your_indicator.txt
```

Each validator runs the same pipeline — file access → marker check → compile → exec → class lookup → metadata → instantiate → soft feature lints — adapted to that extension's contract surface. The indicator validator additionally probes `calculate()` against a synthetic 100-bar OHLCV frame, catching the most common authoring bug (a TA-Lib slice that returns a wrong-length output) before you see a half-blank chart panel.

Exit code is `0` on no errors (warnings are non-fatal); `1` on any error.

### Optional `# plugin-type:` marker (Phase S1)

Every shipped marketplace file declares its extension type as the first non-blank line:

```python
# plugin-type: strategy        # for strategies/*.txt
# plugin-type: indicator       # for indicators/*/*.txt
# plugin-type: plugin-data     # for plugins/data/*.txt (existing)
# plugin-type: plugin-exec     # for plugins/exec/*.txt (existing)
```

The marker is **optional and backward-compatible** for strategies + indicators: pre-S1 files without it still load, and the validator only emits a warning. A *wrong* marker (e.g. a strategy file declaring `plugin-data`) IS an error since it indicates a misplaced file. Plugins continue to require the marker as before — the loader rejects unmarked files in `plugins/{data,exec}/`.

See the OpenTrader-Pro docs (`docs/architecture/plugin_authoring_guide.md`) for the plugin contract surface; strategy + indicator authoring guides are on the Phase S4 roadmap.

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

### Done

- ✅ **Phase M1 — Cryptographic signing** (2026-04-28): Ed25519 `.sig` sibling for every `.txt`; app verifies at load; CI verifies on every commit.
- ✅ **Phase M2 — Trusted-only mode + Developer-mode toggle** (2026-04-28): default-on marketplace_cache + opt-in user-edit dirs. See "Developer Mode" above.
- ✅ **Phase M3 — In-app marketplace installer** (2026-04-28): "Install marketplace files" button in the Accounts panel. Headless CLI via `python -m opentrader.connectors_v2.marketplace_install`.
- ✅ **Phase S3 — Consent gate for strategies + indicators** (2026-04-28): one-time consent dialog covers all three categories; user-edit dirs only load when consent is recorded.
- ✅ **Phase M4 — Marketplace public flip** (2026-04-29): this repository is now public.
- ✅ **Phase S1 — Optional marker lines for strategies + indicators** (2026-04-30): every marketplace `.txt` now declares `# plugin-type: strategy` or `# plugin-type: indicator` as its first non-blank line. Backward-compatible — strategy + indicator loaders still accept unmarked user files, the validator only warns. See "Optional `# plugin-type:` marker" above.
- ✅ **Phase S2 — Validator CLIs for strategies + indicators** (2026-04-30): `python -m opentrader.strategy.validate` + `python -m opentrader.indicators.validate` mirror the plugin validator's pipeline. The indicator validator additionally probes `calculate()` against a synthetic 100-bar OHLCV frame so length/shape mismatches surface before plot time.

### Planned (no committed dates)

- **Phase S4 — Authoring guides for strategies + indicators** (~4-6h): dedicated `strategy_authoring_guide.md` + `indicator_authoring_guide.md` siblings to the existing plugin guide.
- **Auto-update from M3** (deferred to v1.1): the M3 installer is manual today; a future release will check for newer marketplace versions on a cadence and prompt to update.
- **Key rotation infrastructure** (V4): currently a single embedded public key with no expiry or revocation. Multi-key + rotation overlap planned for V4.

The roadmap is tracked in the main app repository.

---

## Links

- Main app: <https://github.com/pparesh25> (OpenTrader-Pro repository)
- Issues / questions: open a GitHub issue against this repository
- License: [GPL-3.0](LICENSE)
