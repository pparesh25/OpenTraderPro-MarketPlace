# Security

This document describes the threat model, current trust posture, and integrity-verification roadmap for files shipped from this marketplace.

---

## ⚠️ Threat model — read first

Every `.txt` file in this repository is **arbitrary Python source code** that the OpenTrader-Pro app loads via `compile()` + `exec()` in an isolated namespace at runtime. Once loaded, the code runs with the **same OS-level privileges as your user account** — it can read your files, talk to the network, place real orders against any configured broker, and persist state to disk.

**This means a malicious file in `~/.opentrader-pro/...` can:**

- Read your secrets (broker API keys, OAuth tokens) from `accounts_v2.json` and the app's keychain integration.
- Place unauthorised real-money orders against any logged-in broker.
- Exfiltrate your portfolio + order history.
- Read or modify any file your user account can read or modify.
- Connect to attacker-controlled hosts.

The risk is **identical to installing any third-party software** — but the friction is lower (a single `cp` command vs. running an installer). Treat the install action accordingly.

---

## Current trust posture (v1 — signed)

The marketplace ships **Ed25519-signed `.txt` files** as of 2026-04-28
(V3 §M1).

| Aspect | Current state |
|---|---|
| File integrity verification on download | ✅ Per-file `<file>.sig` Ed25519 signatures (M1.6) |
| File integrity verification at app load | ✅ Verifier wired into `TextFileLoader` (M1.5); active under "warn" / "required" policy |
| File integrity verification on commit | ✅ GitHub Action `verify-signatures.yml` fails CI on missing/invalid sigs (M1.7) |
| Source review | ✅ Every file is plain Python; reviewable by a developer |
| Public PR review | ✅ All commits land via GitHub PR (you can audit history) |
| Maintainer signing key | ✅ Ed25519 keypair generated 2026-04-28; private key offline at `~/.opentrader-pro-marketplace-keys/private.pem` |
| App-side public key | ✅ Embedded in `opentrader/connectors_v2/marketplace_public_key.py` |
| Trusted-only-mode default | ⏳ Phase M2 — currently "warn" (load with warning on missing sig); strict reject lands with M2 |
| Consent dialog | Plugins ✅ (V3 R1); strategies + indicators ✅ (V3 §S3) |

### Marketplace public key fingerprint

```
/aMy954oy/9Jfm021YWA1PhXDoMBroFiBrOEWh2kq9E=
```

This base64 string is the 32-byte Ed25519 public key. It MUST match
the constant embedded in the OpenTrader Pro app at
`opentrader/connectors_v2/marketplace_public_key.py:MARKETPLACE_PUBLIC_KEY_B64`.
If they ever diverge, signature verification will fail — that's the
intended fail-safe behaviour during a key-rotation transition.

### Practical implication for users

- The OpenTrader Pro app verifies every marketplace file's signature
  before loading it. A tampered file (whether by an attacker, an OS
  rootkit, or your own well-meaning edit) breaks the signature and
  the app refuses to load it.
- An unsigned file (e.g. one you authored yourself outside the
  marketplace) currently loads with a WARNING. After Phase M2 ships,
  unsigned files will be rejected entirely from the marketplace cache
  dir; user-edit dirs (developer mode) keep loading anything.
- The GitHub Action runs on every PR, so a malicious PR that tampers
  with a `.txt` without re-signing fails CI before any merge can
  happen.

### How to verify locally

Pre-app-install (just `cryptography` needed):

```bash
git clone https://github.com/pparesh25/OpenTraderPro-MarketPlace
cd OpenTraderPro-MarketPlace
pip install cryptography
python .github/scripts/verify_signatures.py
```

Expected output: `28 verified, 0 failed`. Any non-zero failure count
means a file is tampered or the public key has rotated and you're on
an old clone — pull the latest commits and re-run.

Post-app-install (uses the embedded verifier):

```bash
python -m opentrader.connectors_v2.signature_verifier <path-to-file.txt>
```

(CLI shim coming in a future minor release; today the verifier is
programmatic only — `from opentrader.connectors_v2.signature_verifier
import verify_file_signature`.)

---

## Integrity-verification roadmap

These are tracked in the main app repository. Versions are not yet released.

### Phase M1 — Cryptographic signing ✅ DONE 2026-04-28

- Maintainer holds an Ed25519 private key offline at
  `~/.opentrader-pro-marketplace-keys/private.pem` (NEVER committed
  to any repository).
- A maintainer-side CLI (`python -m opentrader.connectors_v2.sign`)
  signs every `.txt` file, producing a sibling `<file>.txt.sig` with
  the base64-encoded 64-byte Ed25519 signature over the file content.
- The OpenTrader Pro app embeds the maintainer's public key
  (`marketplace_public_key.py:MARKETPLACE_PUBLIC_KEY` — fingerprint
  above).
- On load, the app verifies the signature against the embedded public
  key. **Mismatch → file is rejected with a clear error.**
- A GitHub Action (`.github/workflows/verify-signatures.yml`) runs on
  every push + PR to `main`. Fails CI if any `.txt` has missing or
  invalid signature. Effect: malicious PRs that tamper with files
  without re-signing cannot land.
- Result: tampering with a downloaded file (by an attacker, an OS
  rootkit, or accidental edit) breaks the signature and the app
  refuses to load it.

### Phase M2 — Trusted-only mode (default) + developer-mode toggle

- The app's Settings panel will default to "marketplace files only" — only files in an app-managed `~/.opentrader-pro/marketplace_cache/` directory will load.
- A separate "Allow custom plugins / strategies / indicators" toggle (off by default) gates the existing `~/.opentrader-pro/{plugins,strategies,indicators}/` paths for users who want to author or sideload files.
- Result: a user who never flips the dev-mode toggle can never accidentally execute a file from outside the verified marketplace.

### Phase M3 — In-app marketplace fetcher

- The Accounts panel "Get example plugins" button will fetch this repository's contents directly via the GitHub API, verify each file's signature, and install into `~/.opentrader-pro/marketplace_cache/...`.
- Files are written read-only (`chmod 0444`) as a defence-in-depth signal.
- Auto-update opt-in: the app can periodically check for new marketplace versions and prompt before installing.

### Phase S3 — Consent gate for strategies + indicators

- Currently the app gates plugins behind a one-time `PluginDisclaimerDialog` (V3 R1). Strategies and indicators have no equivalent gate; any `.txt` dropped into `~/.opentrader-pro/{strategies,indicators}/` loads silently.
- This gap will close before the marketplace publicly recommends installing strategies/indicators from external sources.
- The dialog will be parametrised so each system (plugins / strategies / indicators) records its own consent flag.

---

## Reporting a security issue

If you find a vulnerability — in a marketplace file, in the app's loader, or in the marketplace process itself — please **do not open a public issue**. Email the maintainer directly (see the maintainer's GitHub profile at <https://github.com/pparesh25> for contact). Include:

- A description of the issue and its impact.
- Reproduction steps if available.
- Any suggested mitigation.

Reports will be acknowledged within a reasonable timeframe and patched as quickly as possible. A public disclosure timeline will be agreed on case-by-case basis.

---

## What to do if you suspect a malicious file

If you have any reason to believe a file in `~/.opentrader-pro/...` may be malicious:

1. **Stop the OpenTrader-Pro app immediately.**
2. Move the suspect file out of the watched directory: `mv ~/.opentrader-pro/<path>/<file>.txt /tmp/quarantine/`.
3. Rotate every credential (broker API keys, OAuth tokens) the app has had access to. Issue new keys; revoke old ones from each broker's developer console.
4. Inspect the file with a text editor — Python is human-readable. Look for: network calls to unfamiliar hosts, file operations outside the app's own paths, attempts to read `accounts_v2.json` or anything in `~/.opentrader-pro/keychain/`.
5. If you found a malicious file that you believed came from this marketplace, please report it (see above).

---

## License of this document

This SECURITY.md is part of the marketplace repository and is licensed under [GPL-3.0](LICENSE) along with the rest of the repository.
