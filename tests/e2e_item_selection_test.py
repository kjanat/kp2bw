"""Verify targeted updates, protection and attachment replacement with a live CLI."""

import copy
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from _scope_fixture import create_scope_organization
from e2e_vaultwarden_test import _login_session, _run
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    cert = Path(
        os.environ.get(
            "BW_CERT_PATH", str(root / "tests/fixtures/vaultwarden-certs/cert.pem")
        )
    )
    email = os.environ.get("BW_TEST_EMAIL", "integration@example.com")
    password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        env = os.environ.copy()
        env.update(
            BITWARDENCLI_APPDATA_DIR=str(tmp / "bw"),
            NODE_EXTRA_CA_CERTS=str(cert),
            BW_NOINTERACTION="true",
        )
        _run(["bw", "config", "server", server], env=env)
        _login_session(env, email, password)
        source = tmp / "selection.kdbx"
        db = create_database(source, password="synthetic")
        name = f"Selected item {uuid4()}"
        first = db.add_entry(db.root_group, name, "u", "p")
        second = db.add_entry(db.root_group, name, "u", "p", force_creation=True)
        for entry in (first, second):
            entry.add_attachment(db.add_binary(b"original"), "same.txt")
        db.save()

        def convert(
            entry_id: str | None = None,
            item_id: str | None = None,
            *,
            force: bool = False,
            update: bool = True,
            org: str | None = None,
        ) -> None:
            with patch.dict(os.environ, env):
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
                assert conv.convert() == 0

        def snapshot() -> dict[str, BwItemResponse]:
            with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
                result: dict[str, BwItemResponse] = {}
                for entry in (first, second):
                    item = bw.get_item_by_uuid(entry.uuid.hex.upper())
                    assert item is not None
                    full = bw.get_item(item["id"])
                    # Download URLs carry expiring tokens; compare persisted
                    # metadata, revisions and attachment IDs instead.
                    for attachment in full.get("attachments") or []:
                        attachment.pop("url", None)
                    result[entry.uuid.hex.upper()] = full
                return result

        convert(str(first.uuid))
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            assert bw.get_item_by_uuid(first.uuid.hex.upper()) is not None
            assert bw.get_item_by_uuid(second.uuid.hex.upper()) is None
        convert()
        before = snapshot()
        first_key, second_key = first.uuid.hex.upper(), second.uuid.hex.upper()
        first_id, second_id = before[first_key]["id"], before[second_key]["id"]
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
            first_attachment["id"]
            != (before[first_key].get("attachments") or [])[0]["id"]
        )
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
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

        org = create_scope_organization(server, cert, email, password)
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
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            for item in forced.values():
                bw._request("DELETE", f"/object/item/{item['id']}")
    print("selected sync, force, scope and attachment round trips passed")


if __name__ == "__main__":
    main()
