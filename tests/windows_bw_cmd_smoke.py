"""Live smoke test for invoking an npm-installed ``bw.cmd`` shim on Windows.

Run by the ``windows-bw-cmd`` CI job, which installs the Bitwarden CLI via npm
(producing a ``bw.cmd`` shim with no ``bw.exe``). It proves the two things that
cannot be checked off-Windows:

1. ``resolve_bw_command`` detects the shim and routes it through ``cmd.exe``,
   and that wrapped command actually runs (``bw --version``).
2. A ``bw serve`` launched through the shim can be torn down cleanly by
   ``terminate_serve`` without orphaning the real process on its port.

No vault credentials are required: ``bw serve`` binds its port and answers
``/status`` regardless of auth state, so the lifecycle can be exercised on a
fresh, logged-out CLI.

On non-Windows hosts this is a no-op so the pytest adapter can import it safely.
"""

import os
import socket
import subprocess
import time

import httpx

from kp2bw.bw_serve import resolve_bw_command, terminate_serve


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _port_is_free(port: int) -> bool:
    """True if nothing is listening on *port* (i.e. it can be bound again)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def assert_resolves_cmd_shim() -> tuple[list[str], str | None]:
    argv, cwd = resolve_bw_command()
    if len(argv) <= 1 or not argv[-1].lower().endswith((".cmd", ".bat")):
        raise AssertionError(
            f"expected an npm bw.cmd shim routed through cmd.exe, got {argv!r}"
        )
    return argv, cwd


def assert_version_runs_via_cmd(argv: list[str], cwd: str | None) -> None:
    result = subprocess.run(
        [*argv, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        cwd=cwd,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"bw --version via shim failed (exit {result.returncode}): "
            f"{result.stderr.strip()!r}"
        )
    if not result.stdout.strip():
        raise AssertionError("bw --version via shim produced no output")


def assert_serve_starts_and_tears_down(argv: list[str], cwd: str | None) -> None:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [*argv, "serve", "--port", str(port), "--hostname", "127.0.0.1"],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env={**os.environ},
    )

    try:
        deadline = time.monotonic() + 60
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr = b""
                if proc.stderr is not None:
                    stderr = proc.stderr.read()
                raise AssertionError(
                    f"bw serve exited early (code {proc.returncode}): "
                    f"{stderr.decode('utf-8', 'replace').strip()!r}"
                )
            try:
                # Any HTTP response means the server is up; status is fine even
                # when the vault is locked/unauthenticated.
                _ = httpx.get(f"{base_url}/status", timeout=5)
                ready = True
                break
            except httpx.ConnectError:
                time.sleep(0.25)
        if not ready:
            raise AssertionError("bw serve did not become reachable within 60s")
    finally:
        # Exercise the real teardown: a cmd.exe-wrapped serve must take the
        # whole tree down, not just the wrapper.
        terminate_serve(proc, via_shell=len(argv) > 1, timeout=10)

    if proc.poll() is None:
        raise AssertionError("terminate_serve left the bw serve wrapper running")

    # The decisive check: if the real `bw serve` were orphaned it would still
    # hold the port, so a fresh bind would fail.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _port_is_free(port):
            return
        time.sleep(0.25)
    raise AssertionError(
        f"port {port} still held after teardown — bw serve was orphaned"
    )


def main() -> None:
    if os.name != "nt":
        print("windows bw .cmd smoke: skipped (not Windows)")
        return
    argv, cwd = assert_resolves_cmd_shim()
    assert_version_runs_via_cmd(argv, cwd)
    assert_serve_starts_and_tears_down(argv, cwd)
    print("windows bw .cmd smoke passed")


if __name__ == "__main__":
    main()
