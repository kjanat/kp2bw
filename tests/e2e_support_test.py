import tempfile
from pathlib import Path
from unittest.mock import patch

import e2e_support
from e2e_support import Account, Vault
from scope_fixture import SCOPE_COLLECTION

from kp2bw.exceptions import BitwardenHttpError

MISSING = BitwardenHttpError(
    "bw serve returned HTTP 400 for GET /list/object/org-collections: Organization not found.",
    status_code=400,
)


class Recorder:
    def __init__(
        self,
        visible_after: int | None,
        *,
        missing_until: int = 0,
        error: BitwardenHttpError = MISSING,
    ) -> None:
        self.visible_after = visible_after
        self.missing_until = missing_until
        self.error = error
        self.events: list[str] = []
        self.reads = 0

    def sync(self, *, force: bool = False) -> None:
        assert force
        self.events.append("sync")

    def collections(self, organization: str) -> dict[str, str]:
        assert organization == "org-id"
        self.events.append("read")
        self.reads += 1
        if self.reads <= self.missing_until:
            raise self.error
        if self.visible_after is not None and self.reads > self.visible_after:
            return {SCOPE_COLLECTION: "collection-id"}
        return {}

    def sleep(self, seconds: float) -> None:
        self.events.append(f"sleep {seconds:g}")


def created(*_: object) -> str:
    return "org-id"


def organization(recorder: Recorder) -> str:
    with tempfile.TemporaryDirectory() as directory:
        account = Account(
            server="https://localhost:1",
            cert=Path(directory) / "cert.pem",
            email="user@example.com",
            password="password",
            profile=None,
            container=None,
        )
        vault = Vault(account, Path(directory))
        with (
            patch.object(e2e_support, "create_scope_organization", created),
            patch("time.sleep", recorder.sleep),
            patch.object(vault, "client", recorder, create=True),
            patch.object(vault, "collections", recorder.collections),
        ):
            return vault.organization()


def check_visible_after_stale_reads() -> None:
    recorder = Recorder(visible_after=2)
    assert organization(recorder) == "org-id"
    assert recorder.events == ["sync", "read", "sleep 0.1", "read", "sleep 0.2", "read"]


def check_resyncs_after_a_stale_round() -> None:
    recorder = Recorder(visible_after=6)
    assert organization(recorder) == "org-id"
    assert recorder.events.count("sync") == 2
    assert recorder.events[13:] == ["sync", "read"]


def check_missing_organization_is_stale() -> None:
    recorder = Recorder(visible_after=2, missing_until=2)
    assert organization(recorder) == "org-id"
    assert recorder.events == ["sync", "read", "sleep 0.1", "read", "sleep 0.2", "read"]


def check_other_errors_propagate() -> None:
    error = BitwardenHttpError(
        "bw serve returned HTTP 500 for GET /list/object/org-collections: boom",
        status_code=500,
    )
    recorder = Recorder(visible_after=None, missing_until=1, error=error)
    try:
        _ = organization(recorder)
    except BitwardenHttpError as raised:
        assert raised is error
    else:
        raise AssertionError("An unrelated CLI error must fail the fixture")
    assert recorder.events == ["sync", "read"]


def check_bounded_failure() -> None:
    recorder = Recorder(visible_after=None)
    try:
        _ = organization(recorder)
    except AssertionError as error:
        assert "never became visible" in str(error)
    else:
        raise AssertionError("A missing collection must fail the fixture")
    assert recorder.events.count("sync") == 3
    assert recorder.reads == 18


def main() -> None:
    check_visible_after_stale_reads()
    check_resyncs_after_a_stale_round()
    check_missing_organization_is_stale()
    check_other_errors_propagate()
    check_bounded_failure()
    print("e2e organization visibility wait passed")


if __name__ == "__main__":
    main()
