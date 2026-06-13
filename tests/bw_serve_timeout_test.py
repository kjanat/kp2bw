"""Checks the per-request HTTP timeout override (`KP2BW_HTTP_TIMEOUT`).

`bw serve` forwards item writes to the (possibly self-hosted/remote) Bitwarden
server, so a single create can outlast a short timeout. The default is
deliberately generous and `KP2BW_HTTP_TIMEOUT` lets a user raise it further
without code changes; bad values fall back to the default rather than crashing.
These checks lock that parsing in, exercising the real resolver.
"""

import os
from collections.abc import Generator
from contextlib import contextmanager

from kp2bw.bw_serve import (
    _HTTP_TIMEOUT_ENV,
    _HTTP_TIMEOUT_MAX_S,
    _HTTP_TIMEOUT_S,
    _resolve_http_timeout,
)


@contextmanager
def _env(value: str | None) -> Generator[None]:
    """Set (or unset) KP2BW_HTTP_TIMEOUT for the block, restoring it after."""
    saved = os.environ.get(_HTTP_TIMEOUT_ENV)
    if value is None:
        _ = os.environ.pop(_HTTP_TIMEOUT_ENV, None)
    else:
        os.environ[_HTTP_TIMEOUT_ENV] = value
    try:
        yield
    finally:
        if saved is None:
            _ = os.environ.pop(_HTTP_TIMEOUT_ENV, None)
        else:
            os.environ[_HTTP_TIMEOUT_ENV] = saved


def assert_unset_uses_default() -> None:
    """No env var → the built-in default timeout."""
    with _env(None):
        got = _resolve_http_timeout()
    if got != _HTTP_TIMEOUT_S:
        raise AssertionError(f"expected default {_HTTP_TIMEOUT_S}, got {got}")


def assert_valid_override_applied() -> None:
    """A positive numeric value (int or float form) is used verbatim."""
    with _env("300"):
        if _resolve_http_timeout() != 300.0:
            raise AssertionError("integer override not applied")
    with _env("12.5"):
        if _resolve_http_timeout() != 12.5:
            raise AssertionError("float override not applied")


def assert_invalid_falls_back() -> None:
    """Non-numeric, non-positive, and blank values fall back to the default."""
    for bad in ("abc", "0", "-5", "", "   "):
        with _env(bad):
            got = _resolve_http_timeout()
        if got != _HTTP_TIMEOUT_S:
            raise AssertionError(
                f"{bad!r} should fall back to {_HTTP_TIMEOUT_S}, got {got}"
            )


def assert_above_cap_clamps() -> None:
    """A value above the sanity ceiling is clamped, not honoured verbatim.

    The user clearly meant to raise the timeout (so falling back to the default
    would discard intent), but a typo like ``999999`` shouldn't silently hang a
    migration for hours -- so the resolver clamps to the documented ceiling.
    """
    huge = str(_HTTP_TIMEOUT_MAX_S * 10)
    with _env(huge):
        got = _resolve_http_timeout()
    if got != _HTTP_TIMEOUT_MAX_S:
        raise AssertionError(
            f"{huge!r} should clamp to {_HTTP_TIMEOUT_MAX_S}, got {got}"
        )
    # Exactly the cap is honoured (boundary case: only *above* gets clamped).
    with _env(str(_HTTP_TIMEOUT_MAX_S)):
        got = _resolve_http_timeout()
    if got != _HTTP_TIMEOUT_MAX_S:
        raise AssertionError(f"the cap itself should be honoured verbatim, got {got}")


def main() -> None:
    assert_unset_uses_default()
    assert_valid_override_applied()
    assert_invalid_falls_back()
    assert_above_cap_clamps()
    print("bw serve timeout override test passed")


if __name__ == "__main__":
    main()
