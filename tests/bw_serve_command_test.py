"""Unit tests for bw command resolution and process teardown.

These exercise the platform-branching logic on any OS by patching ``os.name``,
``shutil.which``, and the PATH; the live Windows behaviour is covered separately
by ``tests/windows_bw_cmd_smoke.py`` (run in the Windows CI job).
"""

import subprocess
import sys
from collections.abc import Callable, Mapping
from unittest.mock import patch

from kp2bw import bw_serve
from kp2bw.bw_serve import BW_NOT_FOUND_MSG, resolve_bw_command, terminate_serve
from kp2bw.exceptions import BitwardenClientError


def _fake_which(mapping: Mapping[str, str]) -> Callable[..., str | None]:
    """Build a ``shutil.which`` replacement backed by a name -> path map."""

    def which(name: str, *_args: object, **_kwargs: object) -> str | None:
        return mapping.get(name)

    return which


def _fake_isfile(target: str | None) -> Callable[[str], bool]:
    """Build an ``os.path.isfile`` replacement that matches a single path."""

    def isfile(path: str) -> bool:
        return path == target

    return isfile


def assert_resolve_plain_on_posix() -> None:
    with (
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(
            bw_serve.shutil, "which", _fake_which({"bw": "/usr/local/bin/bw"})
        ),
    ):
        argv, cwd = resolve_bw_command()
    if argv != ["/usr/local/bin/bw"] or cwd is not None:
        raise AssertionError(f"unexpected resolution: {argv!r}, cwd={cwd!r}")


def assert_resolve_windows_exe_direct() -> None:
    exe = r"C:\Program Files\Bitwarden CLI\bw.exe"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.shutil, "which", _fake_which({"bw.exe": exe})),
    ):
        argv, cwd = resolve_bw_command()
    if argv != [exe] or cwd is not None:
        raise AssertionError(f"native exe should run directly: {argv!r}, cwd={cwd!r}")


def assert_resolve_prefers_cmd_over_ps1() -> None:
    # npm ships both bw.cmd and bw.ps1; we must pick the cmd shim.
    shim = r"C:\Users\me\AppData\Roaming\npm\bw.cmd"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.shutil, "which", _fake_which({"bw.cmd": shim})),
    ):
        argv, cwd = resolve_bw_command()
    # COMSPEC may or may not be set on the test host, so only assert the tail.
    if argv[1:] != ["/d", "/c", "bw.cmd"]:
        raise AssertionError(f"shim not routed through cmd.exe: {argv!r}")
    if not argv[0]:
        raise AssertionError("missing command processor in argv[0]")
    if cwd != r"C:\Users\me\AppData\Roaming\npm":
        raise AssertionError(f"shim should run from its own dir, got cwd={cwd!r}")


def assert_resolve_ps1_via_powershell() -> None:
    # A .ps1-only install: shutil.which can't see it (not in PATHEXT), so it is
    # found on PATH and routed through PowerShell.
    ps1 = r"C:\tools\bw.ps1"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.os, "pathsep", ";"),
        patch.object(bw_serve.shutil, "which", _fake_which({})),
        patch.dict(bw_serve.os.environ, {"PATH": r"C:\tools"}, clear=False),
        patch.object(bw_serve.os.path, "isfile", _fake_isfile(ps1)),
    ):
        argv, cwd = resolve_bw_command()
    if argv[0].lower() != "powershell.exe":  # pwsh/powershell not on fake PATH
        raise AssertionError(f"ps1 shim not routed through PowerShell: {argv!r}")
    if argv[-2:] != ["-File", ps1] or "Bypass" not in argv:
        raise AssertionError(f"unexpected PowerShell invocation: {argv!r}")
    if cwd is not None:
        raise AssertionError(f"ps1 invocation should not set cwd, got {cwd!r}")


def assert_resolve_missing_raises_posix() -> None:
    with (
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(bw_serve.shutil, "which", _fake_which({})),
    ):
        try:
            resolve_bw_command()
        except BitwardenClientError as exc:
            if str(exc) != BW_NOT_FOUND_MSG:
                raise AssertionError(f"unexpected message: {exc!r}")
        else:
            raise AssertionError("expected BitwardenClientError when bw is missing")


def assert_resolve_missing_raises_windows() -> None:
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.os, "pathsep", ";"),
        patch.object(bw_serve.shutil, "which", _fake_which({})),
        patch.dict(bw_serve.os.environ, {"PATH": r"C:\tools"}, clear=False),
        patch.object(bw_serve.os.path, "isfile", _fake_isfile(None)),
    ):
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
    assert_resolve_windows_exe_direct()
    assert_resolve_prefers_cmd_over_ps1()
    assert_resolve_ps1_via_powershell()
    assert_resolve_missing_raises_posix()
    assert_resolve_missing_raises_windows()
    assert_terminate_serve_kills_process()
    assert_terminate_serve_noop_when_already_dead()
    print("bw serve command resolution test passed")


if __name__ == "__main__":
    main()
