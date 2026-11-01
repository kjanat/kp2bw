"""Verify historical records and attachment bytes survive real CLI round trips."""

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Literal

from e2e_support import Vault, run, vault_main
from pykeepass import create_database

from kp2bw.attachments import records_from_fields, source_file
from kp2bw.convert import Converter
from kp2bw.history import history_signature
from kp2bw.item_sync import content_signature, stamp_content, sync_stamp_matches

type ItemState = tuple[str, tuple[str, ...]]


def history_scenario(
    vault: Vault, name: str, mode: Literal["cli", "archive", "updates"]
) -> None:
    password = vault.password
    client = vault.client
    path = vault.tmp / f"{name}.kdbx"
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
    archive_env = {"KP2BW_ARCHIVE_HISTORY": "true"}

    def migrate(*, password_history: bool = True) -> None:
        converter = Converter(
            str(path),
            "test",
            None,
            password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
            archive_history=True,
            migrate_password_history=password_history,
        )
        assert converter.convert(client) == 0

    def read() -> tuple[ItemState, bytes, str]:
        nonlocal item_id
        item = vault.item(source_id)
        item_id = item["id"]
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
            client.get_attachment(item_id, original["id"]) == b"original history.json"
        )
        state = (
            item["revisionDate"],
            tuple(sorted(attachment["id"] for attachment in attachments)),
        )
        return state, archive, original["id"]

    try:
        if mode == "cli":
            vault.migrate(path, "test", env=archive_env)
        else:
            migrate()
        initial, raw_archive, original_id = read()
        archive = json.loads(raw_archive)
        assert len(archive["records"]) == 1
        assert "historical notes" in archive["records"][0]["xml"]
        assert "old protected value" in archive["records"][0]["xml"]
        assert (
            base64.b64decode(archive["binaries"][str(binary_id)]["base64"])
            == historical_bytes
        )
        if mode == "cli":
            print("live history archive CLI import passed")
            return
        updated = initial
        if mode == "archive":
            migrate()
            assert read()[0] == initial, (
                "Unchanged history rewrote the item or attachments"
            )
            entry.save_history()
            entry.mtime = datetime(2020, 3, 1, tzinfo=UTC)
            db.save()
            migrate()
            updated, raw_archive, retained_id = read()
            archive = json.loads(raw_archive)
            assert len(archive["records"]) == 2 and retained_id == original_id
            assert updated != initial, "New historical record was not archived"
            migrate()
            assert read()[0] == updated, "Updated archive did not settle into a no-op"

            # Check a fresh sync/export, independent of serve's decrypted cache.
            session = client.inventory_session or ""
            export_env = vault.detached_env({
                "BW_SESSION": session,
                "VW_SESSION": session,
            })
            run(vault.cli_command("sync"), env=export_env, secrets=(session,))
            exported = json.loads(
                run(
                    vault.cli_command("export", "--format", "json", "--raw"),
                    env=export_env,
                    secrets=(session,),
                ).stdout
            )
            exported_item = next(
                item for item in exported["items"] if item["id"] == item_id
            )
            assert history_signature(exported_item) == expected_history
            print("live native history, archive records and export passed")
            return

        supports_updates = client.supports_history_updates()
        entry.history[0].password = "corrected historical password"
        db.save()
        result = vault.kp2bw(
            str(path),
            "--no-metadata",
            "-y",
            expected=0 if supports_updates else 1,
            env={
                **archive_env,
                "KP2BW_KEEPASS_PASSWORD": "test",
                "KP2BW_BITWARDEN_PASSWORD": password,
            },
        )
        if supports_updates:
            expected_history = [
                ("corrected historical password", "2020-02-01T00:00:00.000Z")
            ]
            updated = read()[0]
            migrate()
            assert read()[0] == updated
            assert item_id is not None
            # Seed a verified destination-only record and then change the
            # imported history. The merge must retain the unrelated value.
            item = vault.fresh().get_item(item_id)
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
            migrate()
            expected_history = [
                ("second correction", "2020-02-01T00:00:00.000Z"),
                ("destination-only history", "2019-01-01T00:00:00.000Z"),
            ]
            updated = read()[0]
            migrate()
            assert read()[0] == updated
            entry.delete_history(all=True)
            db.save()
            vault.migrate(
                path,
                "test",
                env={**archive_env, "KP2BW_PASSWORD_HISTORY": "false"},
            )
            assert read()[0] == updated, (
                "Disabled history migration removed imported records"
            )
            migrate()
            expected_history = [
                ("destination-only history", "2019-01-01T00:00:00.000Z")
            ]
            updated = read()[0]
            migrate()
            assert read()[0] == updated, (
                "Empty source history did not settle into a no-op"
            )
        else:
            assert "No item update was sent" in " ".join(result.stderr.split())
            assert read()[0] == updated, (
                "Unsupported update changed the item or its attachments"
            )

        assert item_id is not None
        item = vault.fresh().get_item(item_id)
        original_stamp = content_signature(item)
        if supports_updates:
            histories = item.get("passwordHistory")
            assert histories is not None
            histories[0]["password"] = "manual history edit"
            expected_history[0] = ("manual history edit", expected_history[0][1])
        else:
            item["notes"] = "manual destination edit"
        assert not sync_stamp_matches(item, original_stamp)
        client.update_item(item_id, item)
        protected = read()[0]
        migrate()
        assert read()[0] == protected, "A manual edit was overwritten"
    finally:
        if item_id is not None:
            vault.delete(item_id)
    print("live history update safety, merges and edit protection passed")


def run_history_archive_cli_test(vault: Vault) -> None:
    history_scenario(vault, "history-cli", "cli")


def run_history_archive_test(vault: Vault) -> None:
    history_scenario(vault, "history", "archive")


def run_history_updates_test(vault: Vault) -> None:
    history_scenario(vault, "history-updates", "updates")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_history_archive_cli_test(vault)
        run_history_archive_test(vault)
        run_history_updates_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
