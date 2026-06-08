"""Live smoke test for invoking an npm-installed ``bw`` shim on Windows.

Run by the ``windows-bw-cmd`` CI job, which installs the Bitwarden CLI via npm
(producing ``bw.cmd`` + ``bw.ps1`` with no ``bw.exe``). It proves the two
Windows-specific mechanisms kp2bw relies on, neither of which can be checked
off-Windows:

1. ``resolve_bw_command`` resolves the npm shim and the wrapped command actually
   runs (``bw --version``).
2. ``terminate_serve`` tears down a process launched through a ``cmd.exe``
   wrapper together with its descendants (``taskkill /F /T``), freeing the port
   — a plain ``terminate()`` would orphan the real child behind the wrapper.

``bw serve`` itself requires a logged-in vault ("You are not logged in."), which
isn't available on CI, so the teardown is exercised against a ``cmd.exe -> node``
tree that holds a port — the same process shape ``bw.cmd -> node`` produces.

On non-Windows hosts this is a no-op so the pytest adapter can import it safely.
"""

import os
import socket
import subprocess
import time

from kp2bw.bw_serve import resolve_bw_command, terminate_serve


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _port_accepting(port: int) -> bool:
    """True if something is listening on *port* (a TCP connect succeeds)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _port_is_free(port: int) -> bool:
    """True if nothing holds *port* (i.e. it can be bound again)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def assert_resolves_and_runs() -> None:
    argv, cwd = resolve_bw_command()
    print(f"resolve_bw_command -> {argv!r} (cwd={cwd!r})")
    # npm provides bw.cmd (+ bw.ps1, no bw.exe), so we expect a wrapped shim;
    # accept a native exe too in case the runner image ever ships one.
    runnable = (len(argv) == 1 and argv[0].lower().endswith((".exe", ".com"))) or (
        len(argv) > 1 and argv[-1].lower().endswith((".cmd", ".bat", ".ps1"))
    )
    if not runnable:
        raise AssertionError(f"unexpected bw resolution: {argv!r}")

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
    print(f"bw --version -> {result.stdout.strip()}")


def assert_wrapped_teardown_frees_port() -> None:
    port = _free_port()
    comspec = os.environ.get("COMSPEC", "cmd.exe")
    # cmd.exe -> node holding a port mirrors how bw.cmd -> node would behave.
    # A naive terminate() kills only cmd.exe and leaves node holding the port;
    # terminate_serve(via_shell=True) must take the whole tree down.
    node_script = (
        "const net=require('net');"
        "const srv=net.createServer();"
        f"srv.listen({port}, '127.0.0.1');"
        "setTimeout(()=>{}, 600000);"
    )
    proc = subprocess.Popen(
        [comspec, "/d", "/c", "node", "-e", node_script],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr = b""
                if proc.stderr is not None:
                    stderr = proc.stderr.read()
                raise AssertionError(
                    f"wrapped child exited before binding (code {proc.returncode}): "
                    f"{stderr.decode('utf-8', 'replace').strip()!r}"
                )
            if _port_accepting(port):
                break
            time.sleep(0.25)
        else:
            raise AssertionError("wrapped child never started listening within 30s")
    finally:
        terminate_serve(proc, via_shell=True, timeout=15)

    if proc.poll() is None:
        raise AssertionError("terminate_serve left the cmd.exe wrapper running")

    # The decisive check: taskkill /T must have killed node too. If it were
    # orphaned it would still hold the port and a fresh bind would fail.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _port_is_free(port):
            return
        time.sleep(0.25)
    raise AssertionError(
        f"port {port} still held after teardown — the wrapped child was orphaned"
    )


def main() -> None:
    if os.name != "nt":
        print("windows bw .cmd smoke: skipped (not Windows)")
        return
    assert_resolves_and_runs()
    assert_wrapped_teardown_frees_port()
    print("windows bw .cmd smoke passed")


if __name__ == "__main__":
    main()
