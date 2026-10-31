"""Unit tests for bw command resolution and process teardown.

These exercise the platform-branching logic on any OS by patching ``os.name``,
``shutil.which``, and the PATH; the live Windows behaviour is covered separately
by ``tests/windows_bw_cmd_smoke.py`` (run in the Windows CI job).
"""

import ntpath
import subprocess
import sys
from collections.abc import Callable, Mapping
from unittest.mock import patch

import httpx

from kp2bw import bw_serve
from kp2bw.bw_serve import (
    CLI_NOT_FOUND_MSG,
    resolve_cli_command,
    send_with_retry,
    terminate_serve,
)
from kp2bw.exceptions import BitwardenClientError


def fake_which(mapping: Mapping[str, str]) -> Callable[..., str | None]:
    """Build a ``shutil.which`` replacement backed by a name -> path map."""

    def which(name: str, *args: object, **kwargs: object) -> str | None:
        return mapping.get(name)

    return which


def fake_isfile(target: str | None) -> Callable[[str], bool]:
    """Build an ``os.path.isfile`` replacement that matches a single path."""

    def isfile(path: str) -> bool:
        return path == target

    return isfile


def assert_resolve_plain_on_posix() -> None:
    with (
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(
            bw_serve, "find_cli_executable", fake_which({"bw": "/usr/local/bin/bw"})
        ),
    ):
        argv, cwd = resolve_cli_command()
    if argv != ["/usr/local/bin/bw"] or cwd is not None:
        raise AssertionError(f"unexpected resolution: {argv!r}, cwd={cwd!r}")


def assert_resolve_windows_exe_direct() -> None:
    exe = r"C:\Program Files\Bitwarden CLI\bw.exe"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve, "find_cli_executable", fake_which({"bw.exe": exe})),
    ):
        argv, cwd = resolve_cli_command()
    if argv != [exe] or cwd is not None:
        raise AssertionError(f"native exe should run directly: {argv!r}, cwd={cwd!r}")


def assert_resolve_prefers_cmd_over_ps1() -> None:
    # npm ships both bw.cmd and bw.ps1; we must pick the cmd shim.
    shim = r"C:\Users\me\AppData\Roaming\npm\bw.cmd"
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve, "find_cli_executable", fake_which({"bw.cmd": shim})),
    ):
        argv, cwd = resolve_cli_command()
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
        patch.object(bw_serve, "find_cli_executable", fake_which({})),
        patch.dict(bw_serve.os.environ, {"PATH": r"C:\tools"}, clear=False),
        patch.object(bw_serve.os.path, "isfile", fake_isfile(ps1)),
    ):
        argv, cwd = resolve_cli_command()
    if (
        ntpath.basename(argv[0]).lower() != "powershell.exe"
    ):  # pwsh/powershell not on fake PATH
        raise AssertionError(f"ps1 shim not routed through PowerShell: {argv!r}")
    if argv[-2:] != ["-File", ps1] or "Bypass" not in argv:
        raise AssertionError(f"unexpected PowerShell invocation: {argv!r}")
    if cwd is not None:
        raise AssertionError(f"ps1 invocation should not set cwd, got {cwd!r}")


def assert_resolve_missing_raises_posix() -> None:
    with (
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(bw_serve, "find_cli_executable", fake_which({})),
    ):
        try:
            resolve_cli_command()
        except BitwardenClientError as exc:
            if str(exc) != CLI_NOT_FOUND_MSG:
                raise AssertionError(f"unexpected message: {exc!r}")
        else:
            raise AssertionError("expected BitwardenClientError when bw is missing")


def assert_resolve_missing_raises_windows() -> None:
    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.os, "pathsep", ";"),
        patch.object(bw_serve, "find_cli_executable", fake_which({})),
        patch.dict(bw_serve.os.environ, {"PATH": r"C:\tools"}, clear=False),
        patch.object(bw_serve.os.path, "isfile", fake_isfile(None)),
    ):
        try:
            resolve_cli_command()
        except BitwardenClientError as exc:
            if str(exc) != CLI_NOT_FOUND_MSG:
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
        patch.object(bw_serve, "kill_port_listeners", reaped.append),
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
        send, method="PUT", path="/x", max_attempts=3, sleep=lambda s: None
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
        send_with_retry(send, method="POST", path="/x", sleep=lambda s: None)
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
            send, method="GET", path="/x", max_attempts=2, sleep=lambda s: None
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
        sleep=lambda s: None,
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
            sleep=lambda s: None,
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


def assert_native_vw() -> None:
    with (
        patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "auto"}),
        patch.object(bw_serve.os, "name", "posix"),
        patch.object(bw_serve, "find_cli_executable", fake_which({"vw": "/bin/vw"})),
    ):
        assert resolve_cli_command() == (["/bin/vw", "--nointeraction"], None)
        bw_serve.ensure_cli_available()
    both = {"bw": "/bin/bw", "vw": "/bin/vw"}
    for choice, expected in (("auto", "vw"), ("bw", "bw"), ("vw", "vw")):
        with (
            patch.dict(bw_serve.os.environ, {"KP2BW_CLI": choice}),
            patch.object(bw_serve.os, "name", "posix"),
            patch.object(bw_serve, "find_cli_executable", fake_which(both)),
        ):
            command, _ = resolve_cli_command()
            assert command[0] == both[expected]
    # An explicit choice must never silently select the other vault profile.
    for choice, available in (("vw", "bw"), ("bw", "vw"), ("invalid", "bw")):
        with (
            patch.dict(bw_serve.os.environ, {"KP2BW_CLI": choice}),
            patch.object(bw_serve.os, "name", "posix"),
            patch.object(
                bw_serve,
                "find_cli_executable",
                fake_which({available: f"/bin/{available}"}),
            ),
        ):
            try:
                resolve_cli_command()
            except BitwardenClientError:
                pass
            else:
                raise AssertionError("Explicit CLI selection was ignored")
    with (
        patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "vw"}),
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(
            bw_serve, "find_cli_executable", fake_which({"vw.cmd": r"C:\npm\vw.cmd"})
        ),
    ):
        command, cwd = resolve_cli_command()
        assert command[1:] == ["/d", "/c", "vw.cmd", "--nointeraction"]
        assert cwd == r"C:\npm"
    with patch.dict(
        bw_serve.os.environ,
        {
            "BW_SESSION": "stale-bw",
            "VW_SESSION": "stale-vw",
            "VW_APPDATA_DIR": "/native-vw-profile",
            "BITWARDENCLI_APPDATA_DIR": "/separate-bw-profile",
        },
    ):
        client = object.__new__(bw_serve.BitwardenServeClient)
        client.cli_command = ["vw", "--nointeraction"]
        client.cli_cwd = None
        with patch.object(bw_serve.subprocess, "run") as run:
            client.run_unlock("synthetic-password")
            env = run.call_args.kwargs["env"]
            assert "BW_SESSION" not in env and "VW_SESSION" not in env
            assert env["_KP2BW_BW_PW"] == "synthetic-password"
            assert env["VW_APPDATA_DIR"] == "/native-vw-profile"
        client.serve_port = 12345
        with patch.object(bw_serve.subprocess, "Popen") as spawn:
            client.start_serve("fresh-session")
            env = spawn.call_args.kwargs["env"]
            assert env["VW_SESSION"] == env["BW_SESSION"] == "fresh-session"
            assert spawn.call_args.args[0][:3] == ["vw", "--nointeraction", "serve"]
            client.start_serve(None)
            env = spawn.call_args.kwargs["env"]
            assert "BW_SESSION" not in env and "VW_SESSION" not in env

    with patch.dict(
        bw_serve.os.environ,
        {
            "VW_APPDATA_DIR": "relative vw profile",
            "BITWARDENCLI_APPDATA_DIR": "separate bw profile",
        },
    ):
        env = bw_serve.cli_environment()
        assert env["VW_APPDATA_DIR"] == bw_serve.os.path.abspath("relative vw profile")
        assert env["BITWARDENCLI_APPDATA_DIR"] == bw_serve.os.path.abspath(
            "separate bw profile"
        )


def assert_npx_fallback() -> None:
    package = bw_serve.NPX_VW_PACKAGE
    with (
        patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "auto"}),
        patch.object(bw_serve.os, "name", "posix"),
    ):
        for available, expected in (
            (
                {"vw": "/bin/vw", "bw": "/bin/bw", "npx": "/bin/npx"},
                ["/bin/vw", "--nointeraction"],
            ),
            ({"bw": "/bin/bw", "npx": "/bin/npx"}, ["/bin/bw"]),
            ({"npx": "/bin/npx"}, ["/bin/npx", "--yes", package, "--nointeraction"]),
        ):
            with patch.object(bw_serve, "find_cli_executable", fake_which(available)):
                command, cwd = resolve_cli_command()
                if "npx" in available and not {"vw", "bw"}.intersection(available):
                    assert command[0] == "/bin/npx"
                    assert command[-2:] == [package, "--nointeraction"]
                    assert "--registry=https://registry.npmjs.org/" in command
                    assert "--ignore-scripts" in command
                    assert cwd is None
                else:
                    assert (command, cwd) == (expected, None)
        with (
            patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "vw"}),
            patch.object(
                bw_serve, "find_cli_executable", fake_which({"npx": "/bin/npx"})
            ),
        ):
            try:
                resolve_cli_command()
            except BitwardenClientError:
                pass
            else:
                raise AssertionError("Explicit vw selection silently used npx")
    with (
        patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "auto"}),
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.os.path, "isfile", fake_isfile(None)),
        patch.object(
            bw_serve, "find_cli_executable", fake_which({"npx.cmd": r"C:\npm\npx.cmd"})
        ),
    ):
        command, cwd = resolve_cli_command()
        assert command[1:4] == ["/d", "/c", "npx.cmd"]
        assert command[-2:] == [package, "--nointeraction"]
        assert "--registry=https://registry.npmjs.org/" in command
        assert cwd == r"C:\npm"
    command = ["npx", "--yes", package, "--nointeraction"]
    with patch.object(
        bw_serve.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], 0, "0.1.3\n", ""),
    ) as run:
        assert bw_serve.get_cli_version(command, None) == "0.1.3"
        assert run.call_args.kwargs["timeout"] == 180
    with (
        patch.object(bw_serve, "resolve_cli_command", return_value=(command, None)),
        patch.object(bw_serve, "get_cli_version", return_value="0.1.3"),
        patch.object(
            bw_serve.BitwardenServeClient,
            "get_session",
            return_value="synthetic-session",
        ),
        patch.object(bw_serve.BitwardenServeClient, "start_serve"),
        patch.object(bw_serve.BitwardenServeClient, "wait_for_ready"),
        patch.object(bw_serve.BitwardenServeClient, "unlock"),
        patch.object(bw_serve.BitwardenServeClient, "sync_vault"),
        patch.object(bw_serve.BitwardenServeClient, "list_folders", return_value={}),
        patch.object(bw_serve.BitwardenServeClient, "build_dedup_index"),
        patch.object(
            bw_serve.BitwardenServeClient,
            "request",
            side_effect=AssertionError("Bootstrap must not access a vault"),
        ),
        bw_serve.BitwardenServeClient("synthetic-password") as client,
    ):
        assert package not in client.cli_command
        assert "@kjanat/vaultwarden-cli@0.1.3" in client.cli_command
        assert "--offline" in client.cli_command
    with (
        patch.object(
            bw_serve,
            "resolve_cli_command",
            return_value=(["npx", "--yes", package, "--nointeraction"], None),
        ),
        patch.object(bw_serve, "get_cli_version", return_value=None),
        patch.object(bw_serve.BitwardenServeClient, "get_session") as unlock,
    ):
        try:
            bw_serve.BitwardenServeClient("synthetic-password")
        except BitwardenClientError:
            pass
        else:
            raise AssertionError("Failed npx bootstrap was ignored")
        unlock.assert_not_called()


def assert_windows_excludes_migration_directory() -> None:
    trusted = r"C:\Program Files\Trusted CLI"
    legitimate = ntpath.join(trusted, "bw.cmd")
    looked_up: list[str] = []

    def which(name: str, *args: object, **kwargs: object) -> str | None:
        looked_up.append(name)
        # Model Windows' insecure implicit CWD lookup if called with a bare name.
        if not ntpath.isabs(name):
            return r"C:\migration\vw.cmd"
        return (
            legitimate if ntpath.normcase(name) == ntpath.normcase(legitimate) else None
        )

    with (
        patch.object(bw_serve.os, "name", "nt"),
        patch.object(bw_serve.os, "pathsep", ";"),
        patch.object(bw_serve.os, "getcwd", return_value=r"C:\migration"),
        patch.dict(
            bw_serve.os.environ,
            {
                "KP2BW_CLI": "auto",
                "PATH": f'.;relative;C:\\migration;C:\\MIGRATION\\.;"{trusted}"',
            },
        ),
        patch.object(bw_serve.shutil, "which", which),
        patch.object(bw_serve.os.path, "isfile", return_value=False),
    ):
        command, cwd = resolve_cli_command()
        assert command[1:] == ["/d", "/c", "bw.cmd"]
        assert cwd == trusted
        assert all(ntpath.isabs(name) for name in looked_up)
        assert all(
            not ntpath.normcase(name).startswith(r"c:\migration") for name in looked_up
        )
        assert bw_serve.cli_path_entries() == [trusted]


def assert_npx_environment_isolated() -> None:
    command = ["npx", "--yes", bw_serve.NPX_VW_PACKAGE, "--nointeraction"]
    with patch.dict(
        bw_serve.os.environ,
        {
            "npm_config_registry": "https://untrusted.invalid",
            "NPM_CONFIG_USERCONFIG": "untrusted.npmrc",
            "nPm_CoNfIg_Script_Shell": "untrusted-shell",
            "NODE_OPTIONS": "--require untrusted.js",
            "NODE_PATH": "untrusted-modules",
            "LD_PRELOAD": "untrusted.so",
            "BASH_ENV": "untrusted.sh",
            "NODE_EXTRA_CA_CERTS": "vault-ca.pem",
            "HTTPS_PROXY": "https://untrusted.invalid",
            "VW_APPDATA_DIR": "native-profile",
        },
    ):
        env = bw_serve.cli_environment(command=command)
        for key in (
            "npm_config_registry",
            "NPM_CONFIG_USERCONFIG",
            "nPm_CoNfIg_Script_Shell",
            "NODE_OPTIONS",
            "NODE_PATH",
            "LD_PRELOAD",
            "BASH_ENV",
            "NODE_EXTRA_CA_CERTS",
            "HTTPS_PROXY",
        ):
            assert key not in env
        assert env["VW_APPDATA_DIR"] == bw_serve.os.path.abspath("native-profile")
        with patch.object(
            bw_serve.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "0.1.3\n", ""),
        ) as run:
            assert bw_serve.get_cli_version(command, None) == "0.1.3"
            assert "npm_config_registry" not in run.call_args.kwargs["env"]
            assert "NODE_OPTIONS" not in run.call_args.kwargs["env"]
        # Once authenticated code is cached, offline execution retains the
        # vault's extra CA and freshly issued session without npm config.
        command[2] = "@kjanat/vaultwarden-cli@0.1.3"
        command.insert(2, "--offline")
        env = bw_serve.cli_environment(command=command, session="fresh-session")
        assert env["NODE_EXTRA_CA_CERTS"] == bw_serve.os.path.abspath("vault-ca.pem")
        assert env["VW_SESSION"] == "fresh-session"
        assert "npm_config_registry" not in env and "NODE_OPTIONS" not in env


def main() -> None:
    with patch.dict(bw_serve.os.environ, {"KP2BW_CLI": "auto"}):
        assert_windows_excludes_migration_directory()
        assert_npx_environment_isolated()
        assert_native_vw()
        assert_npx_fallback()
        for version in ("2026.10.1", "0.1.3", "0.2.0-rc.1"):
            for returncode in (0, 1):
                with patch.object(
                    bw_serve.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], returncode, version + "\n", ""
                    ),
                ):
                    assert bw_serve.get_cli_version(["bw"], None) == (
                        version if returncode == 0 else None
                    )
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
