"""``bw unlock`` survives the CLI's user key id backfill failure.

``bw`` 2026.9.0 and later fail an unlock with ``KeyIdBackfillError`` when the
server lacks the user key id endpoint, then start a cooldown that lets the
next unlock through (https://github.com/bitwarden/clients/issues/23937).
These checks drive :meth:`BitwardenServeClient.get_session` with a stubbed
``subprocess.run``, so no ``bw`` process is spawned.
"""

import subprocess
from collections.abc import Sequence
from unittest import mock

from kp2bw import bw_serve
from kp2bw.bw_serve import BitwardenServeClient

BACKFILL_STDERR = (
    "[Encrypted Migrator] Error running migrations for user: 85436923 "
    "Error [KeyIdBackfillError]: API call failed during user key id backfill"
)


class Unlock:
    """Hands out queued ``bw unlock`` outcomes and counts the calls."""

    def __init__(
        self, outcomes: Sequence[subprocess.CompletedProcess[str] | Exception]
    ) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(
        self, args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls += 1
        if not self.outcomes:
            raise AssertionError(f"unexpected extra call: {args}")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def done(
    code: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["bw", "unlock"], code, stdout, stderr)


def session(unlock: Unlock) -> str | None:
    client = object.__new__(BitwardenServeClient)
    client.bw_cmd = ["bw"]
    client.bw_cwd = None
    with (
        mock.patch.object(bw_serve.subprocess, "run", unlock),
        mock.patch.object(bw_serve, "warn_login_compatibility", return_value=None),
    ):
        return client.get_session("master-password")


def assert_backfill_failure_is_retried() -> None:
    unlock = Unlock([done(1, stderr=BACKFILL_STDERR), done(0, stdout="SESSION\n")])
    got = session(unlock)
    if got != "SESSION" or unlock.calls != 2:
        raise AssertionError(
            f"expected the retry's session, got {got!r} after {unlock.calls} calls"
        )


def assert_second_backfill_failure_gives_up() -> None:
    unlock = Unlock([
        done(1, stderr=BACKFILL_STDERR),
        done(1, stderr=BACKFILL_STDERR),
    ])
    got = session(unlock)
    if got is not None or unlock.calls != 2:
        raise AssertionError(
            f"expected None after one retry, got {got!r} after {unlock.calls} calls"
        )


def assert_other_failure_is_not_retried() -> None:
    unlock = Unlock([done(1, stderr="Invalid master password.")])
    got = session(unlock)
    if got is not None or unlock.calls != 1:
        raise AssertionError(
            f"expected one call and None, got {got!r} after {unlock.calls} calls"
        )


def assert_success_is_not_retried() -> None:
    unlock = Unlock([done(0, stdout="SESSION\n")])
    got = session(unlock)
    if got != "SESSION" or unlock.calls != 1:
        raise AssertionError(
            f"expected one call, got {got!r} after {unlock.calls} calls"
        )


def assert_timeout_is_not_retried() -> None:
    unlock = Unlock([subprocess.TimeoutExpired(["bw", "unlock"], 30)])
    got = session(unlock)
    if got is not None or unlock.calls != 1:
        raise AssertionError(
            f"expected one call and None, got {got!r} after {unlock.calls} calls"
        )


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_backfill_failure_is_retried()
    assert_second_backfill_failure_gives_up()
    assert_other_failure_is_not_retried()
    assert_success_is_not_retried()
    assert_timeout_is_not_retried()
    print("bw serve unlock test passed")


if __name__ == "__main__":
    main()
