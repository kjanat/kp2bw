"""Unit tests for bw command resolution and process teardown.

These exercise the platform-branching logic on any OS by patching ``os.name``,
``shutil.which``, and the PATH; the live Windows behaviour is covered separately
by ``tests/windows_bw_cmd_smoke.py`` (run in the Windows CI job).
"""

import subprocess
import sys
from collections.abc import Callable, Mapping
from unittest.mock import patch

import httpx

from kp2bw import bw_serve
from kp2bw.bw_serve import (
    BW_NOT_FOUND_MSG,
    resolve_bw_command,
    send_with_retry,
    terminate_serve,
)
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


def assert_parse_listening_pids_extracts_owner() -> None:
    """Only the LISTENING owner of the exact port is extracted."""
    output = (
        "\n  Proto  Local Address      Foreign Address    State        PID\n"
        "  TCP    127.0.0.1:22650    0.0.0.0:0          LISTENING    4242\n"
        "  TCP    127.0.0.1:139      0.0.0.0:0          LISTENING    4\n"
        "  TCP    127.0.0.1:22650    127.0.0.1:51000    ESTABLISHED  9999\n"
        "  TCP    0.0.0.0:445        0.0.0.0:0          LISTENING    4\n"
    )
    pids = bw_serve.parse_listening_pids(output, 22650)
    if pids != {4242}:
        raise AssertionError(f"expected {{4242}} for the listener, got {pids!r}")
    # An ESTABLISHED connection on the port is not a listener; a free port yields none.
    if bw_serve.parse_listening_pids(output, 51000) != set():
        raise AssertionError("must not match a foreign-address port column")
    if bw_serve.parse_listening_pids(output, 12345) != set():
        raise AssertionError("unused port should yield no pids")


def assert_terminate_serve_reaps_port_when_wrapper_dead() -> None:
    """The regression: wrapper already exited, worker still holds the port.

    terminate_serve must still reap by port on Windows even when the tracked
    process is already dead -- the case the old early-return missed.
    """
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    _ = proc.wait(timeout=5)
    reaped: list[int] = []
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve, "_kill_port_listeners", reaped.append),
    ):
        terminate_serve(proc, via_shell=True, port=22650, timeout=5)
    if reaped != [22650]:
        raise AssertionError(f"expected port 22650 to be reaped, got {reaped!r}")


def assert_send_with_retry_recovers_idempotent() -> None:
    """A transient transport error on an idempotent request is retried away."""
    calls = {"n": 0}
    ok = httpx.Response(200)

    def send() -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ReadError("forcibly closed")
        return ok

    got = send_with_retry(
        send, method="PUT", path="/x", max_attempts=3, sleep=lambda _s: None
    )
    if got is not ok or calls["n"] != 3:
        raise AssertionError(f"idempotent retry should recover; calls={calls['n']}")


def assert_send_with_retry_does_not_retry_post() -> None:
    """A non-idempotent POST is attempted once and not retried (no dup risk)."""
    calls = {"n": 0}

    def send() -> httpx.Response:
        calls["n"] += 1
        raise httpx.ReadError("forcibly closed")

    try:
        send_with_retry(send, method="POST", path="/x", sleep=lambda _s: None)
    except BitwardenClientError:
        pass
    else:
        raise AssertionError("POST transport error must raise, not silently retry")
    if calls["n"] != 1:
        raise AssertionError(f"POST must be attempted exactly once, got {calls['n']}")


def assert_send_with_retry_exhaustion_raises_project_error() -> None:
    """Exhausted retries surface a BitwardenClientError, not a raw httpx error."""

    def send() -> httpx.Response:
        raise httpx.ReadError("forcibly closed")

    try:
        send_with_retry(
            send, method="GET", path="/x", max_attempts=2, sleep=lambda _s: None
        )
    except BitwardenClientError:
        pass
    else:
        raise AssertionError("exhausted retries must raise BitwardenClientError")


def assert_send_with_retry_idempotent_override_retries_post() -> None:
    """An explicit ``idempotent=True`` retries a POST.

    ``/sync`` and ``/unlock`` are POSTs but semantically idempotent (replaying
    them is harmless), so a transient reset on startup must be retried away
    rather than aborting the whole migration before it begins.
    """
    calls = {"n": 0}
    ok = httpx.Response(200)

    def send() -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.ReadError("forcibly closed")
        return ok

    got = send_with_retry(
        send,
        method="POST",
        path="/sync",
        idempotent=True,
        max_attempts=3,
        sleep=lambda _s: None,
    )
    if got is not ok or calls["n"] != 2:
        raise AssertionError(
            f"idempotent=True must retry a POST until it recovers; calls={calls['n']}"
        )


def assert_send_with_retry_idempotent_override_can_force_single_attempt() -> None:
    """An explicit ``idempotent=False`` forces a single attempt even for a GET."""
    calls = {"n": 0}

    def send() -> httpx.Response:
        calls["n"] += 1
        raise httpx.ReadError("forcibly closed")

    try:
        send_with_retry(
            send,
            method="GET",
            path="/x",
            idempotent=False,
            max_attempts=3,
            sleep=lambda _s: None,
        )
    except BitwardenClientError:
        pass
    else:
        raise AssertionError("a forced non-idempotent request must still raise")
    if calls["n"] != 1:
        raise AssertionError(
            f"idempotent=False must force exactly one attempt, got {calls['n']}"
        )


def assert_login_compat_hint_renders_osc8() -> None:
    """``warn_login_compatibility`` prints a clickable OSC 8 link on a terminal.

    ``legacy_windows=False`` is required: Rich strips hyperlinks on the legacy
    Windows console, so without it the link silently degrades even on a forced
    terminal. The shared module console is patched so the public entry point
    renders into a capturable terminal.
    """
    from rich.console import Console

    term = Console(force_terminal=True, legacy_windows=False, width=200)
    with patch.object(bw_serve, "console", term), term.capture() as cap:
        bw_serve.warn_login_compatibility()
    out = cap.get()
    if "\x1b]8;" not in out:
        raise AssertionError(f"expected an OSC 8 hyperlink escape, got {out!r}")
    if bw_serve.TROUBLESHOOTING_LOGIN_404_URL not in out:
        raise AssertionError("troubleshooting URL missing from the OSC 8 sequence")


def assert_login_compat_hint_degrades_to_plain_url() -> None:
    """Without OSC 8 support the URL survives as plain, copyable text.

    A non-terminal sink (pipe/redirect) gets no hyperlink escape, so the URL
    must be the visible link text -- otherwise the address would be lost.
    """
    from rich.console import Console

    plain = Console(force_terminal=False, width=200)
    with patch.object(bw_serve, "console", plain), plain.capture() as cap:
        bw_serve.warn_login_compatibility()
    out = cap.get()
    if "\x1b]8;" in out:
        raise AssertionError(f"non-terminal output must carry no OSC 8 escape: {out!r}")
    if bw_serve.TROUBLESHOOTING_LOGIN_404_URL not in out:
        raise AssertionError(f"URL must remain visible as plain text, got {out!r}")


def main() -> None:
    assert_resolve_plain_on_posix()
    assert_resolve_windows_exe_direct()
    assert_resolve_prefers_cmd_over_ps1()
    assert_resolve_ps1_via_powershell()
    assert_resolve_missing_raises_posix()
    assert_resolve_missing_raises_windows()
    assert_terminate_serve_kills_process()
    assert_terminate_serve_noop_when_already_dead()
    assert_parse_listening_pids_extracts_owner()
    assert_terminate_serve_reaps_port_when_wrapper_dead()
    assert_send_with_retry_recovers_idempotent()
    assert_send_with_retry_does_not_retry_post()
    assert_send_with_retry_exhaustion_raises_project_error()
    assert_send_with_retry_idempotent_override_retries_post()
    assert_send_with_retry_idempotent_override_can_force_single_attempt()
    assert_login_compat_hint_renders_osc8()
    assert_login_compat_hint_degrades_to_plain_url()
    print("bw serve command resolution test passed")


if __name__ == "__main__":
    main()
