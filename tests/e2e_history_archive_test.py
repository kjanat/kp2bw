"""Verify historical records and attachment bytes survive real CLI round trips."""

import base64
import json
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import _login_session, _run, _run_migration
from pykeepass import create_database

from kp2bw._attachments import records_from_fields, source_file
from kp2bw.bw_serve import BitwardenServeClient


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
            BITWARDENCLI_APPDATA_DIR=str(tmp / "profile"),
            NODE_EXTRA_CA_CERTS=cert,
            BW_NOINTERACTION="true",
            KP2BW_ARCHIVE_HISTORY="true",
        )
        _run(["bw", "config", "server", server], env=env)
        _login_session(env, email, password)
        path = tmp / "history.kdbx"
        db = create_database(path, password="test")
        entry = db.add_entry(
            db.root_group, f"history-{uuid.uuid4()}", "user", "old password"
        )
        entry.mtime = datetime(2020, 1, 1, tzinfo=UTC)
        entry.notes = "historical notes"
        entry.set_custom_property("protected", "old protected value", protect=True)
        historical_bytes = b"historical attachment\x00\xff"
        binary_id = db.add_binary(historical_bytes)
        attachment = entry.add_attachment(binary_id, "gone.dat")
        entry.save_history()
        entry.delete_attachment(attachment)
        entry.add_attachment(db.add_binary(b"original history.json"), "history.json")
        entry.password = "current password"
        entry.notes = "current notes"
        entry.set_custom_property("protected", "current protected value", protect=True)
        entry.mtime = datetime(2020, 2, 1, tzinfo=UTC)
        db.save()
        source_id = str(entry.uuid).replace("-", "").upper()
        history_id = source_file("history", "", 1, "history.json", b"").source_id
        item_id: str | None = None

        def read():
            nonlocal item_id
            with patch.dict(os.environ, env), BitwardenServeClient(password) as client:
                found = client.get_item_by_uuid(source_id)
                assert found is not None, "Historical test item missing"
                item_id = found["id"]
                item = client.get_item(item_id)
                records = records_from_fields(item["fields"])
                archive_id = records[history_id].attachment_id
                archive = client.get_attachment(item_id, archive_id)
                attachments = item.get("attachments") or []
                assert len(attachments) == 2
                original = next(
                    attachment
                    for attachment in attachments
                    if attachment["fileName"] == "history.json"
                )
                assert (
                    client.get_attachment(item_id, original["id"])
                    == b"original history.json"
                )
                state = (
                    item["revisionDate"],
                    tuple(sorted(attachment["id"] for attachment in attachments)),
                )
                return state, json.loads(archive), original["id"]

        try:
            _run_migration(path, "test", password, env)
            initial, archive, original_id = read()
            assert len(archive["records"]) == 1
            assert "historical notes" in archive["records"][0]["xml"]
            assert "old protected value" in archive["records"][0]["xml"]
            assert (
                base64.b64decode(archive["binaries"][str(binary_id)]["base64"])
                == historical_bytes
            )
            _run_migration(path, "test", password, env)
            assert read()[0] == initial, (
                "Unchanged history rewrote the item or attachments"
            )
            entry.save_history()
            entry.mtime = datetime(2020, 3, 1, tzinfo=UTC)
            db.save()
            _run_migration(path, "test", password, env)
            updated, archive, retained_id = read()
            assert len(archive["records"]) == 2 and retained_id == original_id
            assert updated != initial, "New historical record was not archived"
            _run_migration(path, "test", password, env)
            assert read()[0] == updated, "Updated archive did not settle into a no-op"
        finally:
            if item_id is not None:
                with (
                    patch.dict(os.environ, env),
                    BitwardenServeClient(password) as client,
                ):
                    client._request("DELETE", f"/object/item/{item_id}")
    print(
        "live history archive, historical bytes, filename collisions and reruns passed"
    )


if __name__ == "__main__":
    main()
