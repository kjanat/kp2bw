"""Verify a missing `bw` CLI yields a friendly error, not a raw traceback."""

import os
import signal
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import patch

from kp2bw import bw_serve
from kp2bw.bw_serve import (
    BW_NOT_FOUND_MSG,
    BitwardenServeClient,
    ensure_bw_available,
)
from kp2bw.exceptions import BitwardenClientError


@contextmanager
def _bw_not_on_path() -> Generator[None]:
    """Point PATH at an empty directory so `shutil.which('bw')` returns None."""
    original = os.environ.get("PATH")
    with tempfile.TemporaryDirectory() as empty_dir:
        os.environ["PATH"] = empty_dir
        try:
            yield
        finally:
            if original is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original


def assert_ensure_raises_friendly_error() -> None:
    with _bw_not_on_path():
        try:
            ensure_bw_available()
        except BitwardenClientError as exc:
            if str(exc) != BW_NOT_FOUND_MSG:
                raise AssertionError(f"unexpected message: {exc!r}")
        else:
            raise AssertionError("expected BitwardenClientError when bw is missing")


def assert_client_init_raises_friendly_error() -> None:
    with _bw_not_on_path():
        try:
            BitwardenServeClient("dummy-password")
        except BitwardenClientError as exc:
            if str(exc) != BW_NOT_FOUND_MSG:
                raise AssertionError(f"unexpected message: {exc!r}")
        except FileNotFoundError as exc:
            raise AssertionError(f"raw FileNotFoundError leaked to caller: {exc!r}")
        else:
            raise AssertionError("expected BitwardenClientError when bw is missing")


def assert_subprocess_filenotfound_is_wrapped() -> None:
    """`bw` on PATH but unexecutable (e.g. Windows `bw.cmd`) is still friendly.

    ``shutil.which`` can locate a ``bw.cmd`` shim via ``PATHEXT`` that
    ``CreateProcess`` then refuses to run, so the subprocess call — not the
    up-front check — is what raises ``FileNotFoundError``. Pretend the lookup
    succeeds but the spawn fails, and assert the constructor still surfaces a
    ``BitwardenClientError`` instead of a raw traceback.
    """
    # __init__ installs signal handlers before the failing subprocess call;
    # snapshot and restore them so a partial construction can't leak state.
    prev_sigterm = signal.getsignal(signal.SIGTERM)
    prev_sigint = signal.getsignal(signal.SIGINT)
    spawn_error = FileNotFoundError(2, "No such file or directory", "bw")
    try:
        with (
            patch.object(bw_serve.shutil, "which", return_value="/fake/bw.cmd"),
            patch.object(bw_serve.subprocess, "run", side_effect=spawn_error),
        ):
            try:
                BitwardenServeClient("dummy-password")
            except BitwardenClientError as exc:
                if str(exc) != BW_NOT_FOUND_MSG:
                    raise AssertionError(f"unexpected message: {exc!r}")
            except FileNotFoundError as exc:
                raise AssertionError(f"raw FileNotFoundError leaked to caller: {exc!r}")
            else:
                raise AssertionError(
                    "expected BitwardenClientError when bw is unexecutable"
                )
    finally:
        signal.signal(signal.SIGTERM, prev_sigterm)
        signal.signal(signal.SIGINT, prev_sigint)


def assert_message_is_actionable() -> None:
    lowered = BW_NOT_FOUND_MSG.lower()
    if "bw" not in lowered or "path" not in lowered:
        raise AssertionError(f"message is not actionable: {BW_NOT_FOUND_MSG!r}")


def main() -> None:
    assert_ensure_raises_friendly_error()
    assert_client_init_raises_friendly_error()
    assert_subprocess_filenotfound_is_wrapped()
    assert_message_is_actionable()
    print("bw serve missing-cli test passed")


if __name__ == "__main__":
    main()
