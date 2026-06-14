"""Manual-edit protection on re-runs (issue #30).

`Converter` stamps a `KP2BW_SYNC` content signature on every item it writes. A
re-run that finds the stamp no longer matching the item's current managed
content knows a *user* edited it in Bitwarden and preserves the edit (outcome
`"protected"`) instead of clobbering it -- unless `--force-update` makes KeePass
win. kp2bw's own writes restamp, so they never self-trip the protection. The
stamp is excluded from the content signature, so it never causes a spurious
diff. Driven with a client double, so no live `bw serve` process is spawned.
"""

from typing import cast

from kp2bw.bw_serve import (
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
    BitwardenServeClient,
)
from kp2bw.bw_types import BwField, BwItemCreate, BwItemResponse
from kp2bw.convert import Converter

_BW_LOGIN = 1


def _make_converter(*, force_update: bool = False) -> Converter:
    """Build a converter against dummy credentials; no I/O happens in __init__."""
    return Converter(
        keepass_file_path="dummy.kdbx",
        keepass_password="pw",
        keepass_keyfile_path=None,
        bitwarden_password="pw",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
        force_update=force_update,
    )


def _field(name: str, value: str) -> BwField:
    return cast(BwField, {"name": name, "value": value, "type": 0})


def _desired(*, name: str, password: str, note: str = "") -> BwItemCreate:
    """A freshly-built item as the migration would emit it (KeePass-authoritative)."""
    return cast(
        BwItemCreate,
        {
            "organizationId": None,
            "collectionIds": [],
            "folderId": None,
            "type": _BW_LOGIN,
            "name": name,
            "notes": note,
            "favorite": False,
            "fields": [_field(KP2BW_ID_FIELD_NAME, "UUID")],
            "login": {
                "uris": [],
                "username": "u",
                "password": password,
                "totp": None,
                "passwordRevisionDate": None,
            },
            "secureNote": None,
            "card": None,
            "identity": None,
        },
    )


def _existing_as_kp2bw_wrote_it(*, name: str, password: str) -> BwItemResponse:
    """An existing vault item carrying the KP2BW_SYNC stamp kp2bw last wrote."""
    item = cast(
        BwItemResponse,
        {
            "id": "item-id",
            "object": "item",
            "revisionDate": "2026-01-01T00:00:00.000Z",
            "organizationId": None,
            "collectionIds": [],
            "folderId": None,
            "type": _BW_LOGIN,
            "name": name,
            "notes": "",
            "favorite": False,
            "fields": [_field(KP2BW_ID_FIELD_NAME, "UUID")],
            "login": {
                "uris": [],
                "username": "u",
                "password": password,
                "totp": None,
                "passwordRevisionDate": None,
            },
            "secureNote": None,
            "card": None,
            "identity": None,
        },
    )
    # Stamp it exactly as _add_bw_entry_to_entries_dict would: the signature of
    # the content kp2bw wrote, excluded from that same signature.
    item["fields"].append(
        _field(KP2BW_SYNC_FIELD_NAME, Converter._content_signature(item))
    )
    return item


class _FakeBw:
    """Records every update_item PUT so a protected item proves it issued none."""

    def __init__(self) -> None:
        self.updated: list[str] = []

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self.updated.append(item_id)

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        pass


def _reconcile(
    converter: Converter, existing: BwItemResponse, desired: BwItemCreate
) -> tuple[str, _FakeBw]:
    bw = _FakeBw()
    outcome, _uploads, _stale = converter._reconcile_existing_item(
        cast(BitwardenServeClient, bw),
        existing,
        None,
        desired,
        [],
        fixed_coll_id=None,
        kp_uuid="UUID",
        force_update=False,
    )
    return outcome, bw


def assert_sync_stamp_excluded_from_signature() -> None:
    """The KP2BW_SYNC stamp must not change the content signature it records."""
    desired = _desired(name="X", password="p")
    sig = Converter._content_signature(desired)
    stamped = cast(BwItemCreate, dict(desired))
    stamped["fields"] = [
        *desired["fields"],
        _field(KP2BW_SYNC_FIELD_NAME, sig),
    ]
    if Converter._content_signature(stamped) != sig:
        raise AssertionError("KP2BW_SYNC stamp must not affect the content signature")


def assert_legacy_item_not_user_modified() -> None:
    """An unstamped (legacy) item is never treated as user-modified."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="p")
    existing["fields"] = [
        f for f in existing["fields"] if f.get("name") != KP2BW_SYNC_FIELD_NAME
    ]
    if Converter._is_user_modified(existing):
        raise AssertionError("an unstamped legacy item must not be protected")


def assert_own_write_not_user_modified() -> None:
    """A freshly kp2bw-stamped item must not look user-modified (no self-trip)."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="p")
    if Converter._is_user_modified(existing):
        raise AssertionError("kp2bw's own write must not trip the protection")


def assert_user_edit_detected() -> None:
    """A Bitwarden-side edit flips the signature, so it is detected."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="orig")
    login = existing.get("login")
    assert login is not None
    login["password"] = "user-edited"
    if not Converter._is_user_modified(existing):
        raise AssertionError("a manual Bitwarden edit must be detected")


def assert_protected_when_user_edited() -> None:
    """User edit + KeePass change + no force -> protected, no PUT issued."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="orig")
    login = existing.get("login")
    assert login is not None
    login["password"] = "user-edited"
    desired = _desired(name="X", password="kp-new")

    outcome, bw = _reconcile(_make_converter(), existing, desired)

    if outcome != "protected":
        raise AssertionError(f"expected 'protected', got {outcome!r}")
    if bw.updated:
        raise AssertionError(f"a protected item must not be PUT: {bw.updated}")


def assert_force_update_overwrites_user_edit() -> None:
    """--force-update overrides protection: KeePass wins, item is PUT."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="orig")
    login = existing.get("login")
    assert login is not None
    login["password"] = "user-edited"
    desired = _desired(name="X", password="kp-new")

    outcome, bw = _reconcile(_make_converter(force_update=True), existing, desired)

    if outcome != "updated":
        raise AssertionError(
            f"expected 'updated' under --force-update, got {outcome!r}"
        )
    if bw.updated != ["item-id"]:
        raise AssertionError(f"forced update must PUT the item: {bw.updated}")


def assert_keepass_change_updates_unedited_item() -> None:
    """KeePass changed but the user did not touch Bitwarden -> normal update."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="orig")
    desired = _desired(name="X", password="kp-new")

    outcome, bw = _reconcile(_make_converter(), existing, desired)

    if outcome != "updated":
        raise AssertionError(f"an unedited item should update, got {outcome!r}")
    if bw.updated != ["item-id"]:
        raise AssertionError(f"the update must PUT the item: {bw.updated}")


def assert_matching_content_skips_regardless_of_edit() -> None:
    """User edit that already matches KeePass content needs no PUT -> skipped."""
    existing = _existing_as_kp2bw_wrote_it(name="X", password="orig")
    login = existing.get("login")
    assert login is not None
    login["password"] = "shared"
    desired = _desired(name="X", password="shared")

    outcome, bw = _reconcile(_make_converter(), existing, desired)

    if outcome != "skipped":
        raise AssertionError(f"matching content should skip, got {outcome!r}")
    if bw.updated:
        raise AssertionError(f"nothing to change, so no PUT: {bw.updated}")


def main() -> None:
    assert_sync_stamp_excluded_from_signature()
    assert_legacy_item_not_user_modified()
    assert_own_write_not_user_modified()
    assert_user_edit_detected()
    assert_protected_when_user_edited()
    assert_force_update_overwrites_user_edit()
    assert_keepass_change_updates_unedited_item()
    assert_matching_content_skips_regardless_of_edit()
    print("protect edits test passed")


if __name__ == "__main__":
    main()
