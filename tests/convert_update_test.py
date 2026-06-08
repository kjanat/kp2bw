"""Unit checks for in-place update of existing Bitwarden entries (issue #11).

Exercises the content-diff, update-payload, and existing-item reconciliation
logic that lets a re-run sync changed KeePass entries (notably edited notes)
onto already-imported Bitwarden items instead of skipping them.

Protected members are exercised through a ``Converter`` subclass (mirroring
``convert_ref_resolution_test``) so the checks stay type-clean.
"""

from typing import Any, cast

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate, BwItemResponse, BwUri
from kp2bw.convert import AttachmentItem, Converter
from kp2bw.exceptions import BitwardenClientError


class UpdateTestConverter(Converter):
    """Converter wired with dummy credentials exposing the methods under test."""

    def __init__(self, *, update_existing: bool = True) -> None:
        """Build a converter that never connects to a live vault."""
        super().__init__(
            keepass_file_path="dummy.kdbx",
            keepass_password="pw",
            keepass_keyfile_path=None,
            bitwarden_password="pw",
            bitwarden_organization_id=None,
            bitwarden_coll_id=None,
            path2name=False,
            path2nameskip=1,
            import_tags=None,
            update_existing=update_existing,
        )

    def diff(self, existing: BwItemResponse, desired: BwItemCreate) -> bool:
        """Public shim for the content-diff check."""
        return self._content_differs(existing, desired)

    def payload(
        self, existing: BwItemResponse, desired: BwItemCreate
    ) -> BwItemResponse:
        """Public shim for building the update payload."""
        return self._build_update_payload(existing, desired)

    def fields_sig(self, fields: list[Any]) -> list[tuple[str, str, int]]:
        """Public shim for the field signature."""
        return self._fields_signature(fields)

    def reconcile(
        self,
        bw: BitwardenServeClient,
        existing: BwItemResponse,
        folder: str | None,
        bw_item: BwItemCreate,
        attachments: list[AttachmentItem],
        *,
        fixed_coll_id: str | None,
    ) -> tuple[str, list[AttachmentItem], dict[str, str]]:
        """Public shim for existing-item reconciliation."""
        return self._reconcile_existing_item(
            bw, existing, folder, bw_item, attachments, fixed_coll_id=fixed_coll_id
        )


def _make_existing(**over: Any) -> BwItemResponse:
    """Build an existing vault item (as returned by the dedup index)."""
    item: dict[str, Any] = {
        "object": "item",
        "id": "item-1",
        "organizationId": None,
        "collectionIds": None,
        "folderId": "folder-1",
        "type": 1,
        "name": "Account",
        "notes": "old note",
        "favorite": True,
        "fields": [{"name": "api", "value": "v1", "type": 0}],
        "login": {
            "uris": [{"uri": "https://a", "match": None}],
            "username": "user",
            "password": "pass",
            "totp": None,
            "passwordRevisionDate": None,
        },
        "secureNote": None,
        "card": None,
        "identity": None,
        "revisionDate": "2020-01-01T00:00:00Z",
    }
    item.update(over)
    return cast(BwItemResponse, item)


def _make_desired(**over: Any) -> BwItemCreate:
    """Build a KeePass-derived item to migrate."""
    item: dict[str, Any] = {
        "organizationId": None,
        "collectionIds": [],
        "folderId": None,
        "type": 1,
        "name": "Account",
        "notes": "old note",
        "favorite": False,
        "fields": [{"name": "api", "value": "v1", "type": 0}],
        "login": {
            "uris": [{"uri": "https://a", "match": None}],
            "username": "user",
            "password": "pass",
            "totp": None,
            "passwordRevisionDate": None,
        },
        "secureNote": None,
        "card": None,
        "identity": None,
    }
    item.update(over)
    return cast(BwItemCreate, item)


class FakeBw:
    """Minimal BitwardenServeClient double for reconciliation tests."""

    def __init__(
        self,
        *,
        existing_attachments: list[dict[str, str]] | None = None,
        attachment_bytes: dict[str, bytes] | None = None,
        fail_get: bool = False,
        fail_update: bool = False,
        fail_get_attachment: bool = False,
    ) -> None:
        self.updates: list[tuple[str, BwItemResponse]] = []
        self.dedup_updates: list[tuple[str | None, str]] = []
        self.deletes: list[tuple[str, str]] = []
        self._attachments = existing_attachments or []
        self._attachment_bytes = attachment_bytes or {}
        self._fail_get = fail_get
        self._fail_update = fail_update
        self._fail_get_attachment = fail_get_attachment

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        if self._fail_update:
            raise BitwardenClientError("simulated update rejection")
        self.updates.append((item_id, item))

    def update_dedup_entry(
        self, folder: str | None, name: str, item: BwItemResponse
    ) -> None:
        self.dedup_updates.append((folder, name))

    def get_item(self, item_id: str) -> BwItemResponse:
        if self._fail_get:
            raise BitwardenClientError("simulated GET failure")
        return cast(BwItemResponse, {"id": item_id, "attachments": self._attachments})

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        if self._fail_get_attachment:
            raise BitwardenClientError("simulated attachment download failure")
        # Fail loudly on an unexpected id: returning b"" would make a wrong-id
        # fetch look like "stale content" and let a refresh-path test pass even
        # if the converter asked for the wrong attachment. AssertionError (not
        # BitwardenClientError) so it isn't swallowed by the differ's guard.
        try:
            return self._attachment_bytes[attachment_id]
        except KeyError as exc:
            raise AssertionError(
                f"Fixture contract broken: unexpected attachment id {attachment_id!r}"
            ) from exc

    def delete_attachment(self, item_id: str, attachment_id: str) -> None:
        self.deletes.append((item_id, attachment_id))


def _as_bw(fake: FakeBw) -> BitwardenServeClient:
    """Treat the structural double as a client for the methods under test."""
    return cast(BitwardenServeClient, fake)


# --------------------------------------------------------------------------
# Content diff
# --------------------------------------------------------------------------


def assert_identical_content_is_idempotent() -> None:
    conv = UpdateTestConverter()
    # favorite differs (True vs False) but kp2bw does not manage favorite, so
    # identical synced content must NOT be treated as a change.
    if conv.diff(_make_existing(), _make_desired()):
        raise AssertionError("identical content should not be flagged as changed")


def assert_notes_change_detected() -> None:
    conv = UpdateTestConverter()
    if not conv.diff(
        _make_existing(notes="old note"), _make_desired(notes="new recovery keys")
    ):
        raise AssertionError("changed notes were not detected")


def assert_none_vs_empty_notes_idempotent() -> None:
    conv = UpdateTestConverter()
    # bw serve returns notes=None for empty notes; desired uses "".
    if conv.diff(_make_existing(notes=None), _make_desired(notes="")):
        raise AssertionError("None vs empty notes should be treated as equal")


def assert_password_change_detected() -> None:
    conv = UpdateTestConverter()
    desired = _make_desired()
    desired["login"]["password"] = "new-pass"
    if not conv.diff(_make_existing(), desired):
        raise AssertionError("changed password was not detected")


def assert_field_change_detected() -> None:
    conv = UpdateTestConverter()
    if not conv.diff(
        _make_existing(),
        _make_desired(fields=[{"name": "api", "value": "v2", "type": 0}]),
    ):
        raise AssertionError("changed custom field was not detected")


def assert_uri_change_detected() -> None:
    conv = UpdateTestConverter()
    desired = _make_desired()
    new_uris: list[BwUri] = [{"uri": "https://b", "match": None}]
    desired["login"]["uris"] = new_uris
    if not conv.diff(_make_existing(), desired):
        raise AssertionError("changed URI was not detected")


def assert_fields_signature_order_independent() -> None:
    conv = UpdateTestConverter()
    a = [
        {"name": "x", "value": "1", "type": 0},
        {"name": "y", "value": "2", "type": 0},
    ]
    b = list(reversed(a))
    if conv.fields_sig(a) != conv.fields_sig(b):
        raise AssertionError("field signature should be order-independent")


# --------------------------------------------------------------------------
# Update payload
# --------------------------------------------------------------------------


def assert_update_payload_preserves_and_overwrites() -> None:
    conv = UpdateTestConverter()
    existing = _make_existing(collectionIds=["c1"])
    desired = _make_desired(notes="new note", collectionIds=["c2"])
    payload = conv.payload(existing, desired)

    if payload["id"] != "item-1":
        raise AssertionError("update payload dropped the item id")
    if payload["favorite"] is not True:
        raise AssertionError("update payload clobbered the user's favorite flag")
    if payload["folderId"] != "folder-1":
        raise AssertionError("update payload dropped the existing folderId")
    if payload["notes"] != "new note":
        raise AssertionError("update payload did not overwrite notes")
    if set(payload["collectionIds"] or []) != {"c1", "c2"}:
        raise AssertionError(
            f"collectionIds should union existing+target, got {payload['collectionIds']}"
        )


def assert_update_payload_preserves_existing_passkey() -> None:
    conv = UpdateTestConverter()
    fido2 = [{"credentialId": "abc", "keyType": "public-key"}]
    existing = _make_existing()
    ex_login = existing.get("login")
    if ex_login is None:
        raise AssertionError("fixture is missing its login object")
    ex_login["fido2Credentials"] = cast(Any, fido2)
    desired = _make_desired(notes="changed")
    payload = conv.payload(existing, desired)
    payload_login = payload.get("login")
    got = payload_login.get("fido2Credentials") if payload_login else None
    if got != fido2:
        raise AssertionError(
            "existing Bitwarden passkey must be preserved when KeePass has none"
        )


# --------------------------------------------------------------------------
# Existing-item reconciliation
# --------------------------------------------------------------------------


def assert_unchanged_entry_is_skipped() -> None:
    conv = UpdateTestConverter()
    bw = FakeBw()
    outcome, missing, _ = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        [],
        fixed_coll_id=None,
    )
    if outcome != "skipped" or missing:
        raise AssertionError(f"unchanged entry should be skipped, got {outcome!r}")
    if bw.updates:
        raise AssertionError("unchanged entry must not issue a PUT")


def assert_changed_notes_trigger_update() -> None:
    conv = UpdateTestConverter()
    bw = FakeBw()
    outcome, _, _ = conv.reconcile(
        _as_bw(bw),
        _make_existing(notes="old"),
        "folder-1",
        _make_desired(notes="new recovery keys"),
        [],
        fixed_coll_id=None,
    )
    if outcome != "updated":
        raise AssertionError(f"changed notes should update, got {outcome!r}")
    if len(bw.updates) != 1 or bw.updates[0][1]["notes"] != "new recovery keys":
        raise AssertionError("update PUT did not carry the new notes")
    if not bw.dedup_updates:
        raise AssertionError("dedup cache should be refreshed after update")


def assert_missing_attachment_is_uploaded() -> None:
    conv = UpdateTestConverter()
    bw = FakeBw(existing_attachments=[])  # item has no attachments yet
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    outcome, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        atts,
        fixed_coll_id=None,
    )
    if [name for name, _ in (cast(tuple[str, str], a) for a in missing)] != ["notes"]:
        raise AssertionError(
            f"missing notes attachment should be queued, got {missing!r}"
        )
    if stale:
        raise AssertionError(f"a brand-new attachment has no stale copy, got {stale!r}")
    # Content unchanged, so the only reason this isn't pure-skip is the upload.
    if outcome != "skipped":
        raise AssertionError(f"expected content outcome 'skipped', got {outcome!r}")


def assert_identical_attachment_not_reuploaded() -> None:
    conv = UpdateTestConverter()
    # Existing notes.txt holds exactly the bytes the KeePass long note would
    # materialise to, so an unchanged re-run must touch nothing.
    bw = FakeBw(
        existing_attachments=[{"id": "att1", "fileName": "notes.txt"}],
        attachment_bytes={"att1": b"y" * 20000},
    )
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    _, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        atts,
        fixed_coll_id=None,
    )
    if missing:
        raise AssertionError("identical attachment must not be re-uploaded (no dups)")
    if stale:
        raise AssertionError("identical attachment must not schedule a delete")


def assert_changed_attachment_is_refreshed() -> None:
    conv = UpdateTestConverter()
    # Existing notes.txt holds stale bytes; the KeePass long note changed but
    # keeps the same filename, so it must be re-uploaded and the old copy
    # scheduled for deletion (content-aware reconciliation, issue #11).
    bw = FakeBw(
        existing_attachments=[{"id": "att1", "fileName": "notes.txt"}],
        attachment_bytes={"att1": b"OLD recovery keys"},
    )
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    _, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        atts,
        fixed_coll_id=None,
    )
    names = [name for name, _ in (cast(tuple[str, str], a) for a in missing)]
    if names != ["notes"]:
        raise AssertionError(
            f"changed attachment should be re-uploaded, got {missing!r}"
        )
    if stale != {"notes.txt": "att1"}:
        raise AssertionError(
            f"stale copy should be scheduled for deletion, got {stale!r}"
        )


def assert_changed_attachment_safe_on_download_failure() -> None:
    conv = UpdateTestConverter()
    # The existing copy cannot be downloaded for comparison; we must not risk a
    # re-upload-and-delete that could lose the only copy -- treat as unchanged.
    bw = FakeBw(
        existing_attachments=[{"id": "att1", "fileName": "notes.txt"}],
        fail_get_attachment=True,
    )
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    _, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        atts,
        fixed_coll_id=None,
    )
    if missing or stale:
        raise AssertionError(
            "on download failure, must not re-upload or delete (avoid data loss)"
        )


def assert_attachment_sync_safe_on_get_failure() -> None:
    conv = UpdateTestConverter()
    bw = FakeBw(fail_get=True)
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    _, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(),
        "folder-1",
        _make_desired(),
        atts,
        fixed_coll_id=None,
    )
    if missing or stale:
        raise AssertionError("on GET failure, must not upload (avoid duplicates)")


def assert_rejected_update_is_non_fatal() -> None:
    conv = UpdateTestConverter()
    # Item has no attachments yet, so without the early return the rejected
    # update would still queue this one — proving the guard, not just the label.
    bw = FakeBw(fail_update=True, existing_attachments=[])
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    outcome, upload, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(notes="old"),
        "folder-1",
        _make_desired(notes="new recovery keys"),
        atts,
        fixed_coll_id=None,
    )
    if outcome != "failed":
        raise AssertionError(
            f"a rejected update PUT must be reported as 'failed', got {outcome!r}"
        )
    if upload or stale:
        raise AssertionError(
            "a failed update must not sync attachments (no half-mutated item)"
        )


def assert_no_update_flag_restores_skip() -> None:
    conv = UpdateTestConverter(update_existing=False)
    bw = FakeBw(existing_attachments=[])
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    outcome, missing, _ = conv.reconcile(
        _as_bw(bw),
        _make_existing(notes="old"),
        "folder-1",
        _make_desired(notes="new"),
        atts,
        fixed_coll_id=None,
    )
    if outcome != "skipped" or missing:
        raise AssertionError("--no-update must restore skip-only behavior")
    if bw.updates:
        raise AssertionError("--no-update must not issue any PUT")


def assert_non_login_collision_is_not_mutated() -> None:
    conv = UpdateTestConverter()
    bw = FakeBw(existing_attachments=[])
    atts: list[AttachmentItem] = [("notes", "y" * 20000)]
    # A secure note (type 2) sharing the (folder, name) must not receive the
    # KeePass login's content or attachments.
    outcome, missing, stale = conv.reconcile(
        _as_bw(bw),
        _make_existing(type=2, notes="old"),
        "folder-1",
        _make_desired(notes="new recovery keys"),
        atts,
        fixed_coll_id=None,
    )
    if outcome != "skipped" or missing or stale:
        raise AssertionError("non-login collision must be skipped with no uploads")
    if bw.updates:
        raise AssertionError("non-login collision must not issue a PUT")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_identical_content_is_idempotent()
    assert_notes_change_detected()
    assert_none_vs_empty_notes_idempotent()
    assert_password_change_detected()
    assert_field_change_detected()
    assert_uri_change_detected()
    assert_fields_signature_order_independent()
    assert_update_payload_preserves_and_overwrites()
    assert_update_payload_preserves_existing_passkey()
    assert_unchanged_entry_is_skipped()
    assert_changed_notes_trigger_update()
    assert_missing_attachment_is_uploaded()
    assert_identical_attachment_not_reuploaded()
    assert_changed_attachment_is_refreshed()
    assert_changed_attachment_safe_on_download_failure()
    assert_attachment_sync_safe_on_get_failure()
    assert_rejected_update_is_non_fatal()
    assert_no_update_flag_restores_skip()
    assert_non_login_collision_is_not_mutated()
    print("convert update test passed")


if __name__ == "__main__":
    main()
