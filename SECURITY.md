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

## Current trust posture (v0)

This is the **initial / unsigned** version of the marketplace.

| Aspect | Current state |
|---|---|
| File integrity verification on download | ❌ None — no hashes, no signatures |
| File integrity verification at app load | ❌ None — app accepts anything in `~/.opentrader-pro/...` |
| Source review | ✅ Every file is plain Python; reviewable by a developer |
| Public PR review | ✅ All commits land via GitHub PR (you can audit history) |
| Maintainer keys | ❌ Not yet — signing infrastructure not yet in place |
| Consent dialog | Plugins ✅ (V3 R1); strategies + indicators ❌ (gap — see roadmap) |

**Practical implication for users today:**

- If you only install files **from this repository** AND verify the file content matches what's published here (e.g. `diff` your local copy against a fresh `git clone`), you have the same trust as you place in the maintainer of this repository.
- If you install files from **any other source** — a friend's copy, a forum post, a downloaded tarball — you have **no integrity guarantee whatsoever**. Read the source before installing.
- A future malicious commit to this repository would currently be detectable only by reading every diff. We're working to make that automatic — see the roadmap below.

---

## Integrity-verification roadmap

These are tracked in the main app repository. Versions are not yet released.

### Phase M1 — Cryptographic signing

- Maintainer holds an Ed25519 private key (offline / cold storage where practical).
- A GitHub Action signs every `.txt` file on commit, producing a sibling `.txt.sig`.
- The OpenTrader-Pro app embeds the maintainer's public key.
- On load, the app re-computes the signature against the file content and verifies against the embedded public key. **Mismatch → file is rejected with a clear error.**
- Result: tampering with a downloaded file (whether by an attacker, an OS rootkit, or your own well-meaning edit) breaks the signature and the app refuses to load it.

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
