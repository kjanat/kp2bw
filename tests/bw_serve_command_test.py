"""Unit tests for bw command resolution and process teardown.

These exercise the platform-branching logic on any OS by patching ``os.name``
and ``shutil.which``; the live Windows ``.cmd`` behaviour is covered separately
by ``tests/windows_bw_cmd_smoke.py`` (run in the Windows CI job).
"""

import subprocess
import sys
from unittest.mock import patch

from kp2bw import bw_serve
from kp2bw.bw_serve import BW_NOT_FOUND_MSG, resolve_bw_command, terminate_serve
from kp2bw.exceptions import BitwardenClientError


def assert_resolve_plain_on_posix() -> None:
    with (
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(bw_serve.shutil, "which", return_value="/usr/local/bin/bw"),
    ):
        argv, cwd = resolve_bw_command()
    if argv != ["/usr/local/bin/bw"] or cwd is not None:
        raise AssertionError(f"unexpected resolution: {argv!r}, cwd={cwd!r}")


def assert_resolve_windows_exe_not_wrapped() -> None:
    exe = r"C:\Program Files\Bitwarden CLI\bw.exe"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.shutil, "which", return_value=exe),
    ):
        argv, cwd = resolve_bw_command()
    if argv != [exe] or cwd is not None:
        raise AssertionError(f"native exe should not be wrapped: {argv!r}, cwd={cwd!r}")


def assert_resolve_wraps_windows_cmd_shim() -> None:
    shim = r"C:\Users\me\AppData\Roaming\npm\bw.cmd"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.shutil, "which", return_value=shim),
    ):
        argv, cwd = resolve_bw_command()
    # COMSPEC may or may not be set on the test host, so only assert the tail.
    if argv[1:] != ["/d", "/c", "bw.cmd"]:
        raise AssertionError(f"shim not routed through cmd.exe: {argv!r}")
    if not argv[0]:
        raise AssertionError("missing command processor in argv[0]")
    if cwd != r"C:\Users\me\AppData\Roaming\npm":
        raise AssertionError(f"shim should run from its own dir, got cwd={cwd!r}")


def assert_resolve_missing_raises() -> None:
    with patch.object(bw_serve.shutil, "which", return_value=None):
        try:
            resolve_bw_command()
        except BitwardenClientError as exc:
            if str(exc) != BW_NOT_FOUND_MSG:
                raise AssertionError(f"unexpected message: {exc!r}")
        else:
            raise AssertionError("expected BitwardenClientError when bw is missing")


def assert_terminate_serve_kills_process() -> None:
    """The non-shell path terminates a real child process (POSIX + Windows)."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        terminate_serve(proc, via_shell=False, timeout=5)
    finally:
        if proc.poll() is None:  # belt-and-suspenders if assertion below fails
            proc.kill()
            _ = proc.wait(timeout=5)
    if proc.poll() is None:
        raise AssertionError("terminate_serve did not stop the process")


def assert_terminate_serve_noop_when_already_dead() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    _ = proc.wait(timeout=5)
    # Must not raise even though the process has already exited.
    terminate_serve(proc, via_shell=True, timeout=5)


def main() -> None:
    assert_resolve_plain_on_posix()
    assert_resolve_windows_exe_not_wrapped()
    assert_resolve_wraps_windows_cmd_shim()
    assert_resolve_missing_raises()
    assert_terminate_serve_kills_process()
    assert_terminate_serve_noop_when_already_dead()
    print("bw serve command resolution test passed")


if __name__ == "__main__":
    main()
