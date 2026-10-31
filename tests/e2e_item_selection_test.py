"""Verify targeted updates, protection and attachment replacement with a live CLI."""

import copy
from uuid import uuid4

from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError


def run_item_selection_test(vault: Vault) -> None:
    password = vault.password
    bw = vault.client
    tmp = vault.tmp
    source = tmp / "selection.kdbx"
    db = create_database(source, password="synthetic")
    name = f"Selected item {uuid4()}"
    first = db.add_entry(db.root_group, name, "u", "p")
    second = db.add_entry(db.root_group, name, "u", "p", force_creation=True)
    for entry in (first, second):
        entry.add_attachment(db.add_binary(b"original"), "same.txt")
    alias = db.add_entry(
        db.root_group,
        "Inbound REF alias",
        "u",
        f"{{REF:P@I:{first.uuid.hex.upper()}}}",
    )
    alias.url = "https://selection-alias.example.test"
    alias.otp = "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP"
    db.save()

    def convert(
        entry_id: str | None = None,
        item_id: str | None = None,
        *,
        force: bool = False,
        update: bool = True,
        org: str | None = None,
    ) -> None:
        conv = Converter(
            str(source),
            "synthetic",
            None,
            password,
            org,
            None,
            False,
            999,
            None,
            entry_id=entry_id,
            item_id=item_id,
            force_update=force,
            update_existing=update,
            migrate_metadata=False,
        )
        assert conv.convert(bw) == 0

    def snapshot() -> dict[str, BwItemResponse]:
        result: dict[str, BwItemResponse] = {}
        for entry in (first, second):
            full = vault.item(entry.uuid.hex.upper())
            # Download URLs carry expiring tokens; compare persisted
            # metadata, revisions and attachment IDs instead.
            for attachment in full.get("attachments") or []:
                attachment.pop("url", None)
            result[entry.uuid.hex.upper()] = full
        return result

    convert(str(first.uuid))
    assert vault.find(first.uuid.hex.upper()) is not None
    assert vault.find(second.uuid.hex.upper()) is None
    convert()
    before = snapshot()
    first_key, second_key = first.uuid.hex.upper(), second.uuid.hex.upper()
    first_id, second_id = before[first_key]["id"], before[second_key]["id"]
    login = before[first_key].get("login")
    assert login is not None and login.get("totp")
    assert any(uri["uri"] == alias.url for uri in login.get("uris") or [])
    convert(str(first.uuid))
    assert snapshot() == before, "Selected rerun removed merged REF data"
    first.notes = "Selected source change"
    second.notes = "Unselected source change"
    first.attachments[0].id = db.add_binary(b"replacement")
    second.attachments[0].id = db.add_binary(b"must not upload")
    db.save()
    convert(str(first.uuid), update=False)
    assert snapshot() == before, "--no-update changed a selected item"
    convert(str(first.uuid))
    changed = snapshot()
    assert changed[second_key] == before[second_key], (
        "Unselected duplicate title changed"
    )
    assert changed[first_key]["notes"] == first.notes
    first_attachment = (changed[first_key].get("attachments") or [])[0]
    assert (
        first_attachment["id"] != (before[first_key].get("attachments") or [])[0]["id"]
    )
    assert bw.get_attachment(first_id, first_attachment["id"]) == b"replacement"
    for key in (first_key, second_key):
        edited = copy.deepcopy(changed[key])
        edited["notes"] = "Destination edit"
        bw.update_item(edited["id"], edited)
    edited_state = snapshot()
    convert(item_id=first_id)
    assert snapshot() == edited_state, "Selected sync overwrote destination edits"
    convert(item_id=first_id, force=True)
    forced = snapshot()
    assert forced[first_key]["notes"] == first.notes
    assert forced[second_key] == edited_state[second_key], (
        "Force escaped item selection"
    )
    convert(str(first.uuid), first_id, force=True)
    assert snapshot() == forced, "Unchanged selected rerun changed revisions/IDs"

    org = vault.organization()
    for entry_id, item_id, scope in (
        (str(uuid4()), None, None),
        (str(first.uuid), second_id, None),
        (None, str(uuid4()), None),
        (str(first.uuid), first_id, org),
    ):
        try:
            convert(entry_id, item_id, org=scope)
        except ConversionError:
            pass
        else:
            raise AssertionError("Invalid or out-of-scope selection succeeded")
        assert snapshot() == forced, "Rejected selection changed vault state"
    vault.delete(*(item["id"] for item in forced.values()))
    print("selected sync, force, scope and attachment round trips passed")


def main() -> None:
    vault_main(run_item_selection_test)


if __name__ == "__main__":
    main()
