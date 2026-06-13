"""Checks that `terminate_serve` actually ends the bw serve process (no orphan/hang).

Regression: on POSIX, `bw` is often a node launcher that spawns a worker, and
killing only the tracked PID left the worker orphaned -- it kept the port and,
when kp2bw's stdout was a pipe, held it open so the parent pipeline never reached
EOF (a multi-minute "still running" hang). `bw serve` is now started in its own
session (`start_new_session=True`) and torn down by signalling the whole process
group. This drives `terminate_serve` against a real grouped process and asserts
it is gone afterwards (and that the call returns promptly, i.e. does not hang).
"""

import os
import subprocess
import sys
import time

from kp2bw.bw_serve import terminate_serve


def assert_terminate_serve_ends_grouped_process() -> None:
    """A process started in its own session is dead after `terminate_serve`."""
    if os.name == "nt":
        print("skip: POSIX process-group teardown test")
        return

    # Mirror _start_serve: a long-lived child in its own session/process group.
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        raise AssertionError("test process exited before teardown")

    start = time.monotonic()
    terminate_serve(proc, timeout=5.0)
    elapsed = time.monotonic() - start

    if proc.poll() is None:
        proc.kill()
        raise AssertionError("process still alive after terminate_serve")
    if elapsed > 10:
        raise AssertionError(f"terminate_serve hung ({elapsed:.1f}s)")


def main() -> None:
    assert_terminate_serve_ends_grouped_process()
    print("bw serve teardown test passed")


if __name__ == "__main__":
    main()
