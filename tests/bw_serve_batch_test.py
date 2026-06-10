"""Resilience of the batch item-create path (issue #24).

A single ``bw serve`` create that times out (``httpx.ReadTimeout``, surfaced as
``BitwardenClientError``) must not abort the whole migration and strand every
entry after it -- the same robustness the update and attachment phases already
have.  These checks drive the per-item (and per-folder) guard in
:meth:`BitwardenServeClient.create_items_batch` with a client double, so no live
``bw serve`` process is spawned.
"""

from collections.abc import Iterable
from typing import cast

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate
from kp2bw.exceptions import BitwardenClientError


def _item(name: str) -> BwItemCreate:
    """Build a minimal create-shaped item carrying only what the batch reads."""
    return cast(BwItemCreate, {"name": name})


class _BatchClient(BitwardenServeClient):
    """Client double whose create_item/create_folder fail for named inputs.

    Bypasses the real ``__init__`` (which would spawn ``bw serve``); only the
    state :meth:`create_items_batch` touches is initialised.  The inherited
    ``create_items_batch`` is the code under test.
    """

    def __init__(
        self,
        *,
        fail_items: Iterable[str] | None = None,
        fail_folders: Iterable[str] | None = None,
    ) -> None:
        self._folders = {}
        self._fail_items = set(fail_items or ())
        self._fail_folders = set(fail_folders or ())
        self.created: list[str] = []
        self.folders_created: list[str] = []

    def create_folder(self, name: str) -> str:
        if name in self._fail_folders:
            raise BitwardenClientError(f"simulated folder failure: {name}")
        self.folders_created.append(name)
        folder_id = f"fid-{name}"
        self._folders[name] = folder_id
        return folder_id

    def create_item(self, item: BwItemCreate) -> str:
        name = item.get("name", "?")
        if name in self._fail_items:
            raise BitwardenClientError(f"simulated create timeout: {name}")
        self.created.append(name)
        return f"id-{name}"


def assert_item_failure_does_not_abort_batch() -> None:
    """The #24 regression: a create timeout mid-batch stranded all later items."""
    bw = _BatchClient(fail_items={"b"})
    entries = {
        "k1": (None, _item("a")),
        "k2": (None, _item("b")),
        "k3": (None, _item("c")),
    }
    key_to_id = bw.create_items_batch(entries)
    if set(key_to_id) != {"k1", "k3"}:
        raise AssertionError(
            f"items before AND after the failure must be created, got {set(key_to_id)}"
        )
    if bw.created != ["a", "c"]:
        raise AssertionError(f"expected a and c created in order, got {bw.created}")


def assert_failed_items_are_reported() -> None:
    """on_item_failed fires once per failed key; on_item_created per success."""
    bw = _BatchClient(fail_items={"b"})
    entries = {
        "k1": (None, _item("a")),
        "k2": (None, _item("b")),
        "k3": (None, _item("c")),
    }
    created: list[int] = []
    failed: list[str] = []
    bw.create_items_batch(
        entries,
        on_item_created=lambda: created.append(1),
        on_item_failed=lambda key, _exc: failed.append(key),
    )
    if failed != ["k2"]:
        raise AssertionError(f"the failed key must be reported once, got {failed}")
    if len(created) != 2:
        raise AssertionError(
            f"on_item_created must fire per success (2), got {len(created)}"
        )


def assert_folder_failure_skips_only_its_items() -> None:
    """A folder that can't be created skips its items, not the whole run.

    An item must never be silently created without its folder (which would
    misplace it into the no-folder root); it is reported as failed instead.
    """
    bw = _BatchClient(fail_folders={"Bad"})
    entries = {
        "k1": ("Good", _item("a")),
        "k2": ("Bad", _item("b")),
        "k3": (None, _item("c")),
    }
    failed: list[str] = []
    key_to_id = bw.create_items_batch(
        entries, on_item_failed=lambda key, _exc: failed.append(key)
    )
    if set(key_to_id) != {"k1", "k3"}:
        raise AssertionError(
            f"items in a good/no folder must be created, got {set(key_to_id)}"
        )
    if failed != ["k2"]:
        raise AssertionError(f"only the bad-folder item should fail, got {failed}")
    if "b" in bw.created:
        raise AssertionError("an item must not be created without its folder")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_item_failure_does_not_abort_batch()
    assert_failed_items_are_reported()
    assert_folder_failure_skips_only_its_items()
    print("bw serve batch test passed")


if __name__ == "__main__":
    main()
