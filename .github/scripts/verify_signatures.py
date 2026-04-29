"""Standalone Ed25519 signature verifier for the OpenTraderPro marketplace.

Self-contained Python script invoked by ``.github/workflows/verify-signatures.yml``
on every PR / push to ``main``. Walks the repository for ``.txt`` files
and verifies each has a valid sibling ``<file>.txt.sig`` against the
embedded marketplace public key.

The script duplicates the verification logic from the OpenTrader Pro
main app (`opentrader/connectors_v2/signature_verifier.py`) so the
marketplace CI doesn't depend on the main app being available — the
two implementations are intentionally identical at the algorithm level
(Ed25519, base64-encoded, detached sigs).

**Key rotation**: when the maintainer rotates the marketplace keypair,
update BOTH constants:

1. ``opentrader/connectors_v2/marketplace_public_key.py`` (main app)
2. ``MARKETPLACE_PUBLIC_KEY_B64`` below (this script)

Then re-sign every marketplace file with the new private key (V3 §M1.4
sign CLI) and bump the app version so users know they need to upgrade
to verify the new signatures.

Exit codes:
    0  — every ``.txt`` had a valid signature.
    1  — at least one missing or invalid signature.
"""

from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# Generated 2026-04-28 — must match
# `opentrader/connectors_v2/marketplace_public_key.py:MARKETPLACE_PUBLIC_KEY_B64`
# in the OpenTrader Pro app source. Update both on key rotation.
MARKETPLACE_PUBLIC_KEY_B64 = "/aMy954oy/9Jfm021YWA1PhXDoMBroFiBrOEWh2kq9E="
MARKETPLACE_PUBLIC_KEY: bytes = base64.b64decode(MARKETPLACE_PUBLIC_KEY_B64)

_ED25519_SIGNATURE_SIZE = 64


def verify_one(content: bytes, sig_b64: str, pub_key: bytes) -> bool:
    """Verify a single (content, sig, pubkey) triple. Never raises."""
    # T-S11-A / F-S11-1 — strict base64 decode. ``validate=False``
    # silently strips characters outside the base64 alphabet, which
    # for cryptographic material means an attacker can prefix garbage
    # like ``!@#`` to shift the decoded byte alignment. Strict mode
    # (``validate=True``) rejects any non-alphabet character; a .sig
    # file MUST contain only the 88-char base64 signature plus
    # optional whitespace (``.strip()`` at the call site).
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(sig) != _ED25519_SIGNATURE_SIZE:
        return False
    # F-S11-10 — split into two branches matching the app-side
    # ``signature_verifier.py`` shape. ``Exception`` already catches
    # ``InvalidSignature`` so the tuple form was redundant; the
    # split-branch form gives CI logs a granular diagnostic
    # (signature mismatch vs unexpected crypto error) without
    # changing the verify outcome.
    try:
        Ed25519PublicKey.from_public_bytes(pub_key).verify(sig, content)
    except InvalidSignature:
        return False
    except Exception:                                  # noqa: BLE001
        # Belt-and-braces: any other crypto error (bad public-key
        # bytes, library-version mismatch) → not verified rather
        # than crashing the workflow.
        return False
    return True


def main(repo_root: Path) -> int:
    txt_files = sorted(repo_root.rglob("*.txt"))
    # Filter out anything inside .git or hidden dirs.
    txt_files = [
        p for p in txt_files
        if not any(part.startswith(".") for part in p.relative_to(repo_root).parts)
    ]

    if not txt_files:
        print("No .txt files found — nothing to verify.")
        return 0

    failures: list[tuple[Path, str]] = []
    valid_count = 0

    for f in txt_files:
        sig_path = f.with_name(f.name + ".sig")
        rel = f.relative_to(repo_root)

        if not sig_path.is_file():
            failures.append((rel, "missing signature"))
            print(f"FAIL  {rel}  (missing .sig)")
            continue

        try:
            content = f.read_bytes()
            sig_b64 = sig_path.read_text(encoding="ascii")
        except OSError as exc:
            failures.append((rel, f"read error: {exc}"))
            print(f"FAIL  {rel}  (read error: {exc})")
            continue

        if verify_one(content, sig_b64, MARKETPLACE_PUBLIC_KEY):
            print(f"ok    {rel}")
            valid_count += 1
        else:
            failures.append((rel, "invalid signature"))
            print(f"FAIL  {rel}  (signature mismatch — file tampered "
                  f"or signed with wrong key)")

    print()
    print("=" * 70)
    print(
        f"Summary: {valid_count} verified, {len(failures)} failed "
        f"out of {len(txt_files)} .txt files."
    )
    if failures:
        print()
        print("Failed files:")
        for path, reason in failures:
            print(f"  - {path}: {reason}")
        return 1
    print()
    print(
        f"All {len(txt_files)} marketplace files verified against "
        f"public key {MARKETPLACE_PUBLIC_KEY_B64}",
    )
    return 0


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    raise SystemExit(main(repo_root))
