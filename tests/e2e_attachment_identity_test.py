"""Round-trip colliding original and generated attachments through the real CLI."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import login_session, run, run_migration
from pykeepass import create_database

from kp2bw.attachments import plan_attachments, records_from_fields, source_file
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate
from kp2bw.convert import Converter
from kp2bw.exceptions import BitwardenClientError


def check_legacy_collision_retry(
    bw: BitwardenServeClient, converter: Converter, *, partial: bool = False
) -> None:
    sources = [
        source_file("original", "legacy.txt", index, "legacy.txt", data)
        for index, data in enumerate((b"first legacy", b"second legacy"), 1)
    ]
    item_id = bw.create_item(
        BwItemCreate(
            name="Legacy collision retry",
            type=1,
            organizationId=None,
            collectionIds=[],
            folderId=None,
            notes=None,
            favorite=False,
            fields=[],
            secureNote=None,
            card=None,
            identity=None,
            login={
                "username": "",
                "password": "",
                "uris": [],
                "totp": None,
                "passwordRevisionDate": None,
            },
        )
    )
    try:
        if partial:
            initial = plan_attachments(sources, {}, [], lambda _: b"")
            assert not bw.upload_attachments([
                (
                    item_id,
                    [(source.filename, source.data) for source in initial.uploads],
                )
            ])
            bw.sync(force=True)
            converter.persist_attachment_plan(
                bw, item_id, initial, {(item_id, initial.sources[0].filename)}
            )
            full = bw.get_item(item_id)
            records = records_from_fields(full["fields"])
            assert set(records) == {sources[1].source_id}
            remote = [(a["id"], a["fileName"]) for a in full.get("attachments") or []]
            assert len(remote) == 2
            recovered = plan_attachments(
                sources, records, remote, lambda aid: bw.get_attachment(item_id, aid)
            )
            assert not recovered.uploads and not recovered.stale
            converter.persist_attachment_plan(bw, item_id, recovered, set())
            full = bw.get_item(item_id)
            assert [
                (a["id"], a["fileName"]) for a in full.get("attachments") or []
            ] == remote
            records = records_from_fields(full["fields"])
            assert set(records) == {source.source_id for source in sources}
            unchanged = plan_attachments(
                sources, records, remote, lambda aid: bw.get_attachment(item_id, aid)
            )
            assert not unchanged.uploads and not unchanged.stale
            return
        assert not bw.upload_attachments([
            (item_id, [(source.original_name, source.data) for source in sources])
        ])
        bw.sync(force=True)
        full = bw.get_item(item_id)
        remote = [(a["id"], a["fileName"]) for a in full.get("attachments") or []]
        plan = plan_attachments(
            sources, {}, remote, lambda aid: bw.get_attachment(item_id, aid)
        )
        assert len(plan.uploads) == 1
        pending = plan.uploads[0]
        assert not bw.upload_attachments([
            (item_id, [(pending.filename, pending.data)])
        ])
        bw.sync(force=True)
        # Model batch verification failing after the server accepted the bytes.
        converter.persist_attachment_plan(
            bw, item_id, plan, {(item_id, pending.filename)}
        )
        full = bw.get_item(item_id)
        records = records_from_fields(full["fields"])
        assert records == plan.records
        remote = [(a["id"], a["fileName"]) for a in full.get("attachments") or []]
        assert len(remote) == 3
        for _ in range(2):
            retry = plan_attachments(
                sources, records, remote, lambda aid: bw.get_attachment(item_id, aid)
            )
            assert not retry.uploads
            assert retry.sources[1].filename == pending.filename
        converter.persist_attachment_plan(bw, item_id, retry, set())
        for stale_id in retry.stale.values():
            bw.delete_attachment(item_id, stale_id)
        bw.sync(force=True)
        full = bw.get_item(item_id)
        records = records_from_fields(full["fields"])
        remote = [(a["id"], a["fileName"]) for a in full.get("attachments") or []]
        assert len(remote) == 2
        unchanged = plan_attachments(
            sources, records, remote, lambda aid: bw.get_attachment(item_id, aid)
        )
        assert not unchanged.uploads and not unchanged.stale
    finally:
        bw.request("DELETE", f"/object/item/{item_id}")


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
            VW_APPDATA_DIR=env.get("KP2BW_E2E_BW_PROFILE", str(tmp / "bw")),
            NODE_EXTRA_CA_CERTS=cert,
            BW_NOINTERACTION="true",
        )
        if env.get("KP2BW_E2E_BW_PROFILE"):
            status = json.loads(run(["bw", "status"], env=env))
            assert status.get("serverUrl", "").rstrip("/") == server.rstrip("/")
            assert status.get("userEmail", "").casefold() == email.casefold()
        else:
            run(["bw", "config", "server", server], env=env)
            login_session(env, email, password)
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
            run_migration(source, "synthetic", password, env)

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

        converter = Converter(
            str(source), "synthetic", None, password, None, None, False, 999, None
        )
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "update_item",
                side_effect=BitwardenClientError(
                    "synthetic initial metadata rejection"
                ),
            ),
        ):
            assert converter.convert() != 0
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "upload_attachments",
                side_effect=AssertionError("First-import retry uploaded another copy"),
            ),
        ):
            assert converter.convert() == 0
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
        # Newly added sources also recover an upload whose association was rejected.
        entry.add_attachment(
            db.add_binary(b"new source after initial migration"), "added.txt"
        )
        db.save()
        added_key = source_file("original", "added.txt", 1, "added.txt", b"").source_id
        expected[added_key] = b"new source after initial migration"
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "update_item",
                side_effect=BitwardenClientError(
                    "synthetic new-source metadata rejection"
                ),
            ),
        ):
            assert converter.convert() != 0
        with (
            patch.dict(os.environ, env),
            patch.object(
                BitwardenServeClient,
                "upload_attachments",
                side_effect=AssertionError("New-source retry uploaded another copy"),
            ),
        ):
            assert converter.convert() == 0
        added = verify()
        assert all(added[1][key] == value for key, value in recovered[1].items())
        migrate()
        assert verify() == added
        db.delete_entry(entry)
        db.save()
        with (
            patch.dict(os.environ, env),
            patch.object(
                converter,
                "persist_attachment_plan",
                side_effect=AssertionError(
                    "A removed entry retained its previous attachment plan"
                ),
            ),
        ):
            assert converter.convert() == 0
        with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
            check_legacy_collision_retry(bw, converter)
            check_legacy_collision_retry(bw, converter, partial=True)
            item = bw.get_item_by_uuid(entry.uuid.hex.upper())
            assert item is not None
            bw.request("DELETE", f"/object/item/{item['id']}")
    print("attachment collision, identity and replacement round trips passed")


if __name__ == "__main__":
    main()
