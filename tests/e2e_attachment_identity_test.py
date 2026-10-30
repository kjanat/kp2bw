"""Round-trip colliding original and generated attachments through the real CLI."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import _login_session, _run, _run_migration
from pykeepass import create_database

from kp2bw._attachments import records_from_fields, source_file
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    cert = os.environ.get(
        "BW_CERT_PATH", str(root / "tests/fixtures/vaultwarden-certs/cert.pem")
    )
    email = os.environ.get("BW_TEST_EMAIL", "integration@example.com")
    password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        env = os.environ.copy()
        env.update(
            BITWARDENCLI_APPDATA_DIR=env.get("KP2BW_E2E_BW_PROFILE", str(tmp / "bw")),
            NODE_EXTRA_CA_CERTS=cert,
            BW_NOINTERACTION="true",
        )
        if env.get("KP2BW_E2E_BW_PROFILE"):
            status = json.loads(_run(["bw", "status"], env=env))
            assert status.get("serverUrl", "").rstrip("/") == server.rstrip("/")
            assert status.get("userEmail", "").casefold() == email.casefold()
        else:
            _run(["bw", "config", "server", server], env=env)
            _login_session(env, email, password)
        source = tmp / "collisions.kdbx"
        db = create_database(source, password="synthetic")
        entry = db.add_entry(db.root_group, "Attachment collisions", "user", "pw")
        entry.notes = "notes" * 3000
        entry.set_custom_property("notes", "custom" * 3000)
        expected: dict[str, bytes] = {}
        for name, values in (
            ("notes.txt", (b"first original", b"second original")),
            ("same.bin", (b"same", b"same")),
        ):
            for ordinal, data in enumerate(values, 1):
                entry.add_attachment(db.add_binary(data), name)
                expected[
                    source_file("original", name, ordinal, name, data).source_id
                ] = data
        expected[source_file("notes", "", 1, "notes.txt", b"").source_id] = (
            entry.notes or ""
        ).encode()
        expected[source_file("field", "notes", 1, "notes.txt", b"").source_id] = (
            b"custom" * 3000
        )
        db.save()

        def migrate() -> None:
            _run_migration(source, "synthetic", password, env)

        def verify() -> tuple[str, dict[str, str]]:
            with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
                item = bw.get_item_by_uuid(entry.uuid.hex.upper())
                assert item is not None
                full = bw.get_item(item["id"])
                records = records_from_fields(full["fields"])
                assert set(records) == set(expected)
                attachments = full.get("attachments") or []
                assert len(attachments) == len(expected)
                assert len({a["fileName"] for a in attachments}) == len(expected)
                assert {a["id"] for a in attachments} == {
                    r.attachment_id for r in records.values()
                }
                for key, data in expected.items():
                    assert (
                        bw.get_attachment(item["id"], records[key].attachment_id)
                        == data
                    )
                return full.get("revisionDate") or "", {
                    key: record.attachment_id for key, record in records.items()
                }

        migrate()
        before = verify()
        migrate()
        assert verify() == before, (
            "Unchanged import changed revisions or attachment IDs"
        )
        replacement_key = source_file(
            "original", "notes.txt", 2, "notes.txt", b""
        ).source_id
        entry.attachments[1].id = db.add_binary(b"replacement for second original")
        expected[replacement_key] = b"replacement for second original"
        db.save()
        migrate()
        after = verify()
        assert after[1][replacement_key] != before[1][replacement_key]
        assert all(
            after[1][key] == value
            for key, value in before[1].items()
            if key != replacement_key
        )
        migrate()
        assert verify() == after
        # An uploaded replacement must not authorize deletion if the ID mapping
        # cannot be saved. The previous association and all old IDs survive.
        entry.attachments[0].id = db.add_binary(b"replacement with rejected metadata")
        db.save()
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "update_item",
                side_effect=BitwardenClientError("synthetic metadata rejection"),
            ),
        ):
            converter = Converter(
                keepass_file_path=str(source),
                keepass_password="synthetic",
                keepass_keyfile_path=None,
                bitwarden_password=password,
                bitwarden_organization_id=None,
                bitwarden_coll_id=None,
                path2name=False,
                path2nameskip=999,
                import_tags=None,
            )
            assert converter.convert() != 0
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            item = bw.get_item_by_uuid(entry.uuid.hex.upper())
            assert item is not None
            full = bw.get_item(item["id"])
            records = records_from_fields(full["fields"])
            assert {
                key: record.attachment_id for key, record in records.items()
            } == after[1]
            assert set(after[1].values()).issubset({
                att["id"] for att in full.get("attachments") or []
            })
        first_key = source_file("original", "notes.txt", 1, "notes.txt", b"").source_id
        expected[first_key] = b"replacement with rejected metadata"
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "upload_attachments",
                side_effect=AssertionError("Retry uploaded another copy"),
            ),
        ):
            assert converter.convert() == 0
        recovered = verify()
        assert recovered[1][first_key] != after[1][first_key]
        migrate()
        assert verify() == recovered
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            item = bw.get_item_by_uuid(entry.uuid.hex.upper())
            assert item is not None
            bw._request("DELETE", f"/object/item/{item['id']}")
    print("attachment collision, identity and replacement round trips passed")


if __name__ == "__main__":
    main()
