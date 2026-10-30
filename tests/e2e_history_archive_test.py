"""Verify historical records and attachment bytes survive real CLI round trips."""

import base64
import json
import os
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import get_session, login_session, run, run_migration
from pykeepass import create_database

from kp2bw.attachments import records_from_fields, source_file
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.history import history_signature
from kp2bw.item_sync import content_signature, stamp_content, sync_stamp_matches


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
        run(["bw", "config", "server", server], env=env)
        login_session(env, email, password)
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
        expected_history = [("old password", "2020-02-01T00:00:00.000Z")]

        def read():
            nonlocal item_id
            with patch.dict(os.environ, env), BitwardenServeClient(password) as client:
                found = client.get_item_by_uuid(source_id)
                assert found is not None, "Historical test item missing"
                item_id = found["id"]
                item = client.get_item(item_id)
                assert history_signature(item) == expected_history, (
                    "Native history values or timestamps differ"
                )
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
            run_migration(path, "test", password, env)
            initial, archive, original_id = read()
            assert len(archive["records"]) == 1
            assert "historical notes" in archive["records"][0]["xml"]
            assert "old protected value" in archive["records"][0]["xml"]
            assert (
                base64.b64decode(archive["binaries"][str(binary_id)]["base64"])
                == historical_bytes
            )
            run_migration(path, "test", password, env)
            assert read()[0] == initial, (
                "Unchanged history rewrote the item or attachments"
            )
            entry.save_history()
            entry.mtime = datetime(2020, 3, 1, tzinfo=UTC)
            db.save()
            run_migration(path, "test", password, env)
            updated, archive, retained_id = read()
            assert len(archive["records"]) == 2 and retained_id == original_id
            assert updated != initial, "New historical record was not archived"
            run_migration(path, "test", password, env)
            assert read()[0] == updated, "Updated archive did not settle into a no-op"

            # Check a fresh sync/export, independent of serve's decrypted cache.
            session = get_session(env, password)
            run(["bw", "sync", "--session", session], env=env)
            exported = json.loads(
                run(
                    ["bw", "export", "--format", "json", "--raw", "--session", session],
                    env=env,
                )
            )
            exported_item = next(
                item for item in exported["items"] if item["id"] == item_id
            )
            assert history_signature(exported_item) == expected_history

            with patch.dict(os.environ, env), BitwardenServeClient(password) as client:
                supports_updates = client.supports_history_updates()
            entry.history[0].password = "corrected historical password"
            db.save()
            command_env = {
                **env,
                "KP2BW_KEEPASS_PASSWORD": "test",
                "KP2BW_BITWARDEN_PASSWORD": password,
            }
            result = subprocess.run(
                ["uv", "run", "kp2bw", str(path), "--no-metadata", "-y"],
                env=command_env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            assert result.returncode == (0 if supports_updates else 1), (
                "Unexpected history-update result"
            )
            if supports_updates:
                expected_history = [
                    ("corrected historical password", "2020-02-01T00:00:00.000Z")
                ]
                updated = read()[0]
                run_migration(path, "test", password, env)
                assert read()[0] == updated
                assert item_id is not None
                # Seed a verified destination-only record and then change the
                # imported history. The merge must retain the unrelated value.
                with (
                    patch.dict(os.environ, env),
                    BitwardenServeClient(password) as client,
                ):
                    item = client.get_item(item_id)
                    histories = item.get("passwordHistory")
                    assert histories is not None
                    histories.append({
                        "password": "destination-only history",
                        "lastUsedDate": "2019-01-01T00:00:00.000Z",
                    })
                    stamp_content(item)
                    client.update_item(item_id, item)
                entry.history[0].password = "second correction"
                db.save()
                run_migration(path, "test", password, env)
                expected_history = [
                    ("second correction", "2020-02-01T00:00:00.000Z"),
                    ("destination-only history", "2019-01-01T00:00:00.000Z"),
                ]
                updated = read()[0]
                run_migration(path, "test", password, env)
                assert read()[0] == updated
            else:
                assert "No item update was sent" in " ".join(result.stderr.split())
                assert read()[0] == updated, (
                    "Unsupported update changed the item or its attachments"
                )

            assert item_id is not None
            with patch.dict(os.environ, env), BitwardenServeClient(password) as client:
                item = client.get_item(item_id)
                original_stamp = content_signature(item)
                if supports_updates:
                    histories = item.get("passwordHistory")
                    assert histories is not None
                    histories[0]["password"] = "manual history edit"
                    expected_history[0] = (
                        "manual history edit",
                        "2020-02-01T00:00:00.000Z",
                    )
                else:
                    item["notes"] = "manual destination edit"
                assert not sync_stamp_matches(item, original_stamp)
                client.update_item(item_id, item)
            protected = read()[0]
            run_migration(path, "test", password, env)
            assert read()[0] == protected, "A manual edit was overwritten"
        finally:
            if item_id is not None:
                with (
                    patch.dict(os.environ, env),
                    BitwardenServeClient(password) as client,
                ):
                    client.request("DELETE", f"/object/item/{item_id}")
    print("live native history, export, update safety, archive and reruns passed")


if __name__ == "__main__":
    main()
