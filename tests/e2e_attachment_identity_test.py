"""Round-trip colliding original and generated attachments through the real CLI."""

from unittest.mock import patch

from e2e_support import Vault, vault_main
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
        retries = [
            plan_attachments(
                sources, records, remote, lambda aid: bw.get_attachment(item_id, aid)
            )
            for _ in range(2)
        ]
        for attempt in retries:
            assert not attempt.uploads
            assert attempt.sources[1].filename == pending.filename
        retry = retries[-1]
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


class IdentityFixture:
    def __init__(self, vault: Vault, name: str) -> None:
        self.vault = vault
        self.source = vault.tmp / f"{name}.kdbx"
        self.db = create_database(self.source, password="synthetic")
        self.entry = self.db.add_entry(
            self.db.root_group, "Attachment collisions", "user", "pw"
        )
        self.entry.notes = "notes" * 3000
        self.entry.set_custom_property("notes", "custom" * 3000)
        self.expected: dict[str, bytes] = {}
        for file_name, values in (
            ("notes.txt", (b"first original", b"second original")),
            ("same.bin", (b"same", b"same")),
        ):
            for ordinal, data in enumerate(values, 1):
                self.entry.add_attachment(self.db.add_binary(data), file_name)
                self.expected[
                    source_file(
                        "original", file_name, ordinal, file_name, data
                    ).source_id
                ] = data
        self.expected[source_file("notes", "", 1, "notes.txt", b"").source_id] = (
            self.entry.notes or ""
        ).encode()
        self.expected[source_file("field", "notes", 1, "notes.txt", b"").source_id] = (
            b"custom" * 3000
        )
        self.db.save()

    def converter(self) -> Converter:
        return Converter(
            keepass_file_path=str(self.source),
            keepass_password="synthetic",
            keepass_keyfile_path=None,
            bitwarden_password=self.vault.password,
            bitwarden_organization_id=None,
            bitwarden_coll_id=None,
            path2name=False,
            path2nameskip=999,
            import_tags=None,
        )

    def migrate(self) -> None:
        converter = Converter(
            str(self.source),
            "synthetic",
            None,
            self.vault.password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
        )
        assert converter.convert(self.vault.client) == 0

    def verify(self) -> tuple[str, dict[str, str]]:
        full = self.vault.item(self.entry.uuid.hex.upper())
        records = records_from_fields(full["fields"])
        assert set(records) == set(self.expected)
        attachments = full.get("attachments") or []
        assert len(attachments) == len(self.expected)
        assert len({a["fileName"] for a in attachments}) == len(self.expected)
        assert {a["id"] for a in attachments} == {
            r.attachment_id for r in records.values()
        }
        for key, data in self.expected.items():
            assert (
                self.vault.client.get_attachment(full["id"], records[key].attachment_id)
                == data
            )
        return full["revisionDate"], {
            key: record.attachment_id for key, record in records.items()
        }

    def converged(self) -> tuple[str, dict[str, str]]:
        self.migrate()
        state = self.verify()
        self.migrate()
        assert self.verify() == state, (
            "Unchanged import changed revisions or attachment IDs"
        )
        return state

    def delete(self) -> None:
        self.vault.delete(self.vault.item(self.entry.uuid.hex.upper())["id"])


def run_attachment_identity_test(vault: Vault) -> None:
    fixture = IdentityFixture(vault, "collisions")
    bw = vault.client
    db, entry, expected = fixture.db, fixture.entry, fixture.expected
    migrate, verify = fixture.migrate, fixture.verify
    converter = fixture.converter()
    with (
        patch.object(
            BitwardenServeClient,
            "update_item",
            side_effect=BitwardenClientError("synthetic initial metadata rejection"),
        ),
    ):
        assert converter.convert(bw) != 0
    with (
        patch.object(
            BitwardenServeClient,
            "upload_attachments",
            side_effect=AssertionError("First-import retry uploaded another copy"),
        ),
    ):
        assert converter.convert(bw) == 0
    before = verify()
    migrate()
    assert verify() == before, "Unchanged import changed revisions or attachment IDs"
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
    fixture.delete()
    print("attachment collision, identity and replacement round trips passed")


def run_attachment_rejected_test(vault: Vault) -> None:
    fixture = IdentityFixture(vault, "collisions-rejected")
    bw = vault.client
    db, entry, expected = fixture.db, fixture.entry, fixture.expected
    migrate, verify = fixture.migrate, fixture.verify
    after = fixture.converged()
    # An uploaded replacement must not authorize deletion if the ID mapping
    # cannot be saved. The previous association and all old IDs survive.
    entry.attachments[0].id = db.add_binary(b"replacement with rejected metadata")
    db.save()
    converter = fixture.converter()
    with (
        patch.object(
            BitwardenServeClient,
            "update_item",
            side_effect=BitwardenClientError("synthetic metadata rejection"),
        ),
    ):
        assert converter.convert(bw) != 0
    full = vault.item(entry.uuid.hex.upper())
    records = records_from_fields(full["fields"])
    assert {key: record.attachment_id for key, record in records.items()} == after[1]
    assert set(after[1].values()).issubset({
        att["id"] for att in full.get("attachments") or []
    })
    first_key = source_file("original", "notes.txt", 1, "notes.txt", b"").source_id
    expected[first_key] = b"replacement with rejected metadata"
    with (
        patch.object(
            BitwardenServeClient,
            "upload_attachments",
            side_effect=AssertionError("Retry uploaded another copy"),
        ),
    ):
        assert converter.convert(bw) == 0
    recovered = verify()
    assert recovered[1][first_key] != after[1][first_key]
    migrate()
    assert verify() == recovered
    fixture.delete()
    print("attachment replacement with a rejected association recovered")


def run_attachment_added_test(vault: Vault) -> None:
    fixture = IdentityFixture(vault, "collisions-added")
    bw = vault.client
    db, entry, expected = fixture.db, fixture.entry, fixture.expected
    migrate, verify = fixture.migrate, fixture.verify
    recovered = fixture.converged()
    converter = fixture.converter()
    # Newly added sources also recover an upload whose association was rejected.
    entry.add_attachment(
        db.add_binary(b"new source after initial migration"), "added.txt"
    )
    db.save()
    added_key = source_file("original", "added.txt", 1, "added.txt", b"").source_id
    expected[added_key] = b"new source after initial migration"
    with (
        patch.object(
            BitwardenServeClient,
            "update_item",
            side_effect=BitwardenClientError("synthetic new-source metadata rejection"),
        ),
    ):
        assert converter.convert(bw) != 0
    with (
        patch.object(
            BitwardenServeClient,
            "upload_attachments",
            side_effect=AssertionError("New-source retry uploaded another copy"),
        ),
    ):
        assert converter.convert(bw) == 0
    added = verify()
    assert all(added[1][key] == value for key, value in recovered[1].items())
    migrate()
    assert verify() == added
    db.delete_entry(entry)
    db.save()
    with (
        patch.object(
            converter,
            "persist_attachment_plan",
            side_effect=AssertionError(
                "A removed entry retained its previous attachment plan"
            ),
        ),
    ):
        assert converter.convert(bw) == 0
    fixture.delete()
    print("new attachment source with a rejected association recovered")


def run_attachment_legacy_test(vault: Vault) -> None:
    converter = Converter(
        keepass_file_path=str(vault.tmp / "unused-legacy.kdbx"),
        keepass_password="synthetic",
        keepass_keyfile_path=None,
        bitwarden_password=vault.password,
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=999,
        import_tags=None,
    )
    check_legacy_collision_retry(vault.client, converter)
    check_legacy_collision_retry(vault.client, converter, partial=True)
    print("legacy attachment collision retry round trips passed")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_attachment_identity_test(vault)
        run_attachment_rejected_test(vault)
        run_attachment_added_test(vault)
        run_attachment_legacy_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
