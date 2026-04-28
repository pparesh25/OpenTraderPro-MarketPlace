"""Cross-repo public-key drift check (T-S11-B / F-S11-2).

The marketplace verifier embeds ``MARKETPLACE_PUBLIC_KEY_B64`` in
``verify_signatures.py`` and the OpenTrader-Pro app embeds the same
constant in ``opentrader/connectors_v2/marketplace_public_key.py``.
The two MUST stay byte-identical: a maintainer who rotates the key in
one repo and forgets the other gets silent verification breakage in
opposite directions (CI accepts a sig the app rejects, or vice versa).

This script fetches the app's source over raw GitHub and asserts the
local constant matches. Run from the marketplace CI workflow so a
drift fails the PR rather than reaching production.

Behaviour:

* Both constants present + identical → exit 0.
* Both constants present + different → exit 1, diagnostic on stderr.
* Network / fetch failure → exit 2, distinct from drift so CI logs
  make the cause obvious. (The marketplace verify still runs against
  the local constant, so a transient network blip doesn't gate the
  whole workflow on this check.)

The drift exit (1) is retained as a hard failure because it indicates
a real maintenance bug — the two repos disagree about the trust
anchor. The fetch exit (2) is retained as a soft warning so an
outage of GitHub raw doesn't unrelatedly break marketplace publishes.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


# Two fetch modes:
#
# 1. Unauthenticated raw GitHub — works when the app repo is public
#    (the post-M4 default). No token required.
# 2. Authenticated GitHub API — works when the app repo is private,
#    PROVIDED the marketplace workflow has access to a personal-access
#    token (PAT) with read scope on OpenTrader-Pro. The PAT lives as a
#    GitHub Actions secret named ``OPENTRADER_PRO_READ_TOKEN`` and is
#    surfaced via the workflow's ``env:`` block.
#
# When the token is set, the API path takes precedence. When it is
# not, the raw URL is tried; a 404 / network error soft-fails (exit 2)
# so a private app repo without a configured token logs a warning
# rather than gating the marketplace publish on a check that cannot
# succeed.
_APP_KEY_RAW_URL = (
    "https://raw.githubusercontent.com/pparesh25/OpenTrader-Pro/main/"
    "opentrader/connectors_v2/marketplace_public_key.py"
)
_APP_KEY_API_URL = (
    "https://api.github.com/repos/pparesh25/OpenTrader-Pro/contents/"
    "opentrader/connectors_v2/marketplace_public_key.py?ref=main"
)
_TOKEN_ENV_VAR = "OPENTRADER_PRO_READ_TOKEN"
_FETCH_TIMEOUT_SEC = 30.0
_KEY_RE = re.compile(
    r'^MARKETPLACE_PUBLIC_KEY_B64\s*=\s*"([^"]+)"\s*$', re.MULTILINE,
)


def _read_local_key(script_path: Path) -> str | None:
    """Extract MARKETPLACE_PUBLIC_KEY_B64 from the sibling verifier."""
    try:
        text = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: cannot read {script_path}: {exc}", file=sys.stderr)
        return None
    match = _KEY_RE.search(text)
    if match is None:
        print(
            f"ERROR: MARKETPLACE_PUBLIC_KEY_B64 not found in {script_path}",
            file=sys.stderr,
        )
        return None
    return match.group(1)


def _fetch_via_raw(url: str) -> tuple[str | None, str | None]:
    """Plain raw GitHub fetch (works when the app repo is public)."""
    try:
        with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT_SEC) as resp:
            return resp.read().decode("utf-8"), None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        return None, f"raw fetch failed: {exc}"


def _fetch_via_api(url: str, token: str) -> tuple[str | None, str | None]:
    """Authenticated GitHub API fetch with base64-encoded body."""
    import base64 as _b64
    import json as _json

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SEC) as resp:
            payload = _json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        return None, f"API fetch failed: {exc}"
    content_b64 = payload.get("content", "")
    if not content_b64:
        return None, "API response missing 'content' field"
    try:
        text = _b64.b64decode(content_b64).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        return None, f"API response decode failed: {exc}"
    return text, None


def _fetch_app_key() -> tuple[str | None, str | None]:
    """Return ``(key, error)`` — exactly one is non-None.

    Prefers the authenticated API path when a token is set, falls
    back to the unauthenticated raw URL otherwise.
    """
    token = os.environ.get(_TOKEN_ENV_VAR, "").strip()
    if token:
        text, err = _fetch_via_api(_APP_KEY_API_URL, token)
    else:
        text, err = _fetch_via_raw(_APP_KEY_RAW_URL)
    if text is None:
        return None, err
    match = _KEY_RE.search(text)
    if match is None:
        return None, (
            "MARKETPLACE_PUBLIC_KEY_B64 not found in fetched app source"
        )
    return match.group(1), None


def main() -> int:
    script_path = Path(__file__).resolve().parent / "verify_signatures.py"
    local_key = _read_local_key(script_path)
    if local_key is None:
        return 1

    app_key, fetch_err = _fetch_app_key()
    if app_key is None:
        # Network / fetch failure — soft-fail so a transient outage
        # (or a private app repo without a configured token) doesn't
        # gate the whole CI workflow on this check.
        print(
            f"WARNING: could not fetch app key for drift check ({fetch_err}). "
            f"Marketplace verify still proceeds against local key. "
            f"To enable authenticated checks against a private app repo, "
            f"set the {_TOKEN_ENV_VAR} env var (typically via a workflow "
            f"secret).",
            file=sys.stderr,
        )
        return 2

    if local_key == app_key:
        print(
            f"OK: marketplace verifier key matches app key:\n  {local_key}",
        )
        return 0

    print(
        "FAIL: MARKETPLACE_PUBLIC_KEY_B64 drift between repos.\n"
        f"  marketplace ({script_path.name}): {local_key}\n"
        f"  app         ({_APP_KEY_RAW_URL.rsplit('/', 1)[-1]}): {app_key}\n"
        f"\n"
        f"Update BOTH constants on key rotation:\n"
        f"  - OpenTraderPro-MarketPlace/.github/scripts/verify_signatures.py\n"
        f"  - OpenTrader-Pro/opentrader/connectors_v2/marketplace_public_key.py",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
