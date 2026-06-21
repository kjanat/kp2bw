"""Per-entry resilience of the convert orchestrator (issue #24 family).

A transient ``bw serve`` transport failure while processing a single entry must
degrade to a non-fatal skip, not abort the whole migration and strand every
entry after it.  These checks drive the guarded helpers that wrap the orchestra-
tor's per-entry HTTP calls (collection resolution, pre-attachment sync) with
client doubles, so no live ``bw serve`` process is spawned.
"""

from typing import Any, cast

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError


class ResilienceTestConverter(Converter):
    """Converter wired with dummy credentials exposing the guarded helpers."""

    def __init__(self, *, coll_id: str | None = "auto") -> None:
        super().__init__(
            keepass_file_path="dummy.kdbx",
            keepass_password="pw",
            keepass_keyfile_path=None,
            bitwarden_password="pw",
            bitwarden_organization_id="org-1",
            bitwarden_coll_id=coll_id,
            path2name=False,
            path2nameskip=1,
            import_tags=None,
        )

    def resolve_collection_safely(
        self,
        bw: BitwardenServeClient,
        bw_item: BwItemCreate,
        folder: str | None,
        firstlevel: str | None,
    ) -> bool:
        """Public shim for the guarded collection resolution."""
        return self._resolve_collection_safely(bw, bw_item, folder, firstlevel)

    def sync_safely(self, bw: BitwardenServeClient) -> None:
        """Public shim for the guarded pre-attachment sync."""
        self._sync_safely(bw)


class _FakeBw:
    """Client double whose org-collection create and sync can be scripted to fail."""

    def __init__(
        self,
        *,
        fail_collection: bool = False,
        fail_sync: bool = False,
        coll_id: str = "coll-1",
    ) -> None:
        self._fail_collection = fail_collection
        self._fail_sync = fail_sync
        self._coll_id = coll_id
        self.calls: list[str] = []
        self.sync_attempts = 0

    def create_org_collection(self, name: str) -> str | None:
        self.calls.append(name)
        if self._fail_collection:
            raise BitwardenClientError(f"simulated collection POST failure: {name}")
        return self._coll_id

    def sync(self) -> None:
        self.sync_attempts += 1
        if self._fail_sync:
            raise BitwardenClientError("simulated sync failure")


def _bw_item() -> BwItemCreate:
    return cast(BwItemCreate, {"name": "Account", "collectionIds": []})


def _as_bw(fake: _FakeBw) -> BitwardenServeClient:
    return cast(BitwardenServeClient, fake)


def assert_collection_failure_is_non_fatal() -> None:
    """A dropped org-collection POST must not propagate; the entry is skipped."""
    conv = ResilienceTestConverter()
    bw = _FakeBw(fail_collection=True)
    bw_item = _bw_item()
    ok = conv.resolve_collection_safely(_as_bw(bw), bw_item, "Team/Servers", "Team")
    if ok:
        raise AssertionError("a failed collection resolution must report False")
    if bw_item.get("collectionIds"):
        raise AssertionError("a failed resolution must not assign a collection")


def assert_collection_success_assigns_and_reports_true() -> None:
    conv = ResilienceTestConverter()
    bw = _FakeBw(coll_id="coll-9")
    bw_item = _bw_item()
    ok = conv.resolve_collection_safely(_as_bw(bw), bw_item, "Team/Servers", "Team")
    if not ok:
        raise AssertionError("a successful resolution must report True")
    if bw.calls != ["Team"]:
        raise AssertionError(
            f"auto collection mode should use top-level folder, got {bw.calls}"
        )
    if cast(Any, bw_item).get("collectionIds") != ["coll-9"]:
        raise AssertionError(
            f"resolution must assign the collection, got {bw_item.get('collectionIds')}"
        )


def assert_nested_collection_uses_full_folder_path() -> None:
    conv = ResilienceTestConverter(coll_id="nested")
    bw = _FakeBw(coll_id="coll-nested")
    bw_item = _bw_item()
    ok = conv.resolve_collection_safely(_as_bw(bw), bw_item, "Team/Servers", "Team")
    if not ok:
        raise AssertionError("a successful nested resolution must report True")
    if bw.calls != ["Team/Servers"]:
        raise AssertionError(
            f"nested collection mode should use full folder path, got {bw.calls}"
        )
    if cast(Any, bw_item).get("collectionIds") != ["coll-nested"]:
        raise AssertionError(
            f"nested resolution must assign the collection, got {bw_item.get('collectionIds')}"
        )


def assert_pre_attachment_sync_failure_is_non_fatal() -> None:
    """A dropped pre-attachment sync must not abort: the upload phase self-heals.

    Items are already created by this point; ``upload_attachment`` does its own
    sync-and-retry, so a failed pre-emptive sync is swallowed rather than losing
    a run whose items already landed.
    """
    conv = ResilienceTestConverter()
    bw = _FakeBw(fail_sync=True)
    conv.sync_safely(_as_bw(bw))  # must not raise
    if bw.sync_attempts != 1:
        raise AssertionError(
            f"sync_safely must attempt the sync once, got {bw.sync_attempts}"
        )


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_collection_failure_is_non_fatal()
    assert_collection_success_assigns_and_reports_true()
    assert_nested_collection_uses_full_folder_path()
    assert_pre_attachment_sync_failure_is_non_fatal()
    print("convert resilience test passed")


if __name__ == "__main__":
    main()
