"""Persist JSON and safely upgrade historical YAML through the real CLI."""

import copy
import json
import logging
import uuid
from datetime import UTC, datetime

from e2e_support import Vault, vault_main
from pykeepass import create_database

from kp2bw.attachments import records_from_fields
from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.item_sync import pre_history_content_signature, stamp_content

logger = logging.getLogger("e2e.metadata")


def metadata(item: BwItemResponse) -> str | None:
    matches = [f["value"] for f in item["fields"] if f["name"] == "KP2BW_META"]
    assert len(matches) <= 1, "Duplicated metadata field"
    if not matches:
        return None
    assert isinstance(matches[0], str)
    return matches[0]


def run_metadata_test(vault: Vault) -> None:
    """Use an existing authenticated profile and clean up only owned fixtures."""
    password = vault.password
    source = vault.tmp / "metadata.kdbx"
    kp_password = "SyntheticMetadataPassword123!"
    db = create_database(source, password=kp_password)
    run_id = uuid.uuid4().hex
    names: dict[str, str] = {}
    source_ids: set[str] = set()
    tags = ["b", "a", "café", "line\nbreak", "\u0085\u2028\u2029"]
    expiry = datetime(2040, 1, 1, tzinfo=UTC)
    expected = {"expires": expiry.isoformat(), "tags": tags}
    for case in ("fresh", "yaml", "unstamped", "edited-meta", "edited-notes", "empty"):
        name = f"Metadata {run_id} {case}"
        names[case] = name
        entry = db.add_entry(
            db.root_group, name, "synthetic-user", "synthetic-password"
        )
        source_ids.add(entry.uuid.hex.upper())
        if case != "empty":
            entry.tags = tags
            entry.expires = True
            entry.expiry_time = expiry
    db.save()

    def read_items() -> dict[str, BwItemResponse]:
        items = vault.items()
        result: dict[str, BwItemResponse] = {}
        for case, name in names.items():
            matches = [item for item in items if item.get("name") == name]
            assert len(matches) == 1, "Missing or duplicated metadata fixture"
            result[case] = matches[0]
        return result

    def migrate() -> None:
        converter = Converter(
            str(source), kp_password, None, password, None, None, False, 999, None
        )
        assert converter.convert(vault.client) == 0

    try:
        logger.info("Checking persisted JSON tags and expiry")
        vault.migrate(source, kp_password, metadata=True)
        initial = read_items()
        for case, item in initial.items():
            value = metadata(item)
            if case == "empty":
                assert value is None, "Empty metadata should be omitted"
            else:
                assert value is not None and json.loads(value) == expected

        # Seed the actual historical wire representation, including its stamp.
        # Preserve this literal independently of today's metadata serializer.
        old_yaml = "expires: '2040-01-01T00:00:00+00:00'\ntags:\n- b\n- a\n- \"caf\\xE9\"\n- 'line\n\n  break'\n- \"\\N\\L\\P\""
        bw = vault.client
        for case in ("yaml", "unstamped", "edited-meta", "edited-notes"):
            item = copy.deepcopy(initial[case])
            for field in item["fields"]:
                if field["name"] == "KP2BW_META":
                    field["value"] = old_yaml
            stamp_content(item)
            if case == "unstamped":
                item["fields"] = [
                    f for f in item["fields"] if f["name"] != "KP2BW_SYNC"
                ]
            elif case == "edited-meta":
                for field in item["fields"]:
                    if field["name"] == "KP2BW_META":
                        field["value"] = "tags:\n- manually-edited"
            elif case == "edited-notes":
                item["notes"] = "Manually edited in Bitwarden"
            bw.update_item(str(item["id"]), item)
        seeded = read_items()
        assert metadata(seeded["yaml"]) == old_yaml
        logger.info("Checking safe YAML upgrades and protected manual edits")
        migrate()
        upgraded = read_items()
        for case in ("yaml", "unstamped"):
            assert upgraded[case]["id"] == seeded[case]["id"]
            value = metadata(upgraded[case])
            assert value is not None and json.loads(value) == expected
            assert upgraded[case]["revisionDate"] != seeded[case]["revisionDate"]
        for case in ("fresh", "edited-meta", "edited-notes", "empty"):
            assert upgraded[case] == seeded[case], (
                "Untouched or protected item was rewritten"
            )
        logger.info("Checking metadata-enabled unchanged rerun")
        migrate()
        assert read_items() == upgraded, "Metadata rerun changed content or revisions"
    finally:
        vault.delete_sources(source_ids, names.values())
    check_legacy_ref_upgrade(vault)
    print("live JSON metadata and YAML upgrade regression passed")


def check_legacy_ref_upgrade(vault: Vault) -> None:
    bw = vault.client
    source = vault.tmp / "legacy-ref-metadata.kdbx"
    db = create_database(source, password="synthetic")
    entry = db.add_entry(
        db.root_group, "Legacy REF metadata", "user", "pw", url="https://target.example"
    )
    entry.tags = ["x" * 11000]
    entry.set_custom_property("KP2BW_HISTORY", "ordinary source field")
    db.add_entry(
        db.root_group,
        "Alias",
        "user",
        f"{{REF:P@I:{entry.uuid.hex}}}",
        url="https://alias.example",
    )
    db.save()
    converter = Converter(
        str(source),
        "synthetic",
        None,
        vault.password,
        None,
        None,
        False,
        999,
        None,
        migrate_password_history=False,
    )
    converter.prepare_entries()
    desired = converter.unpack_entry(converter.entries[entry.uuid.hex.upper()])[2]
    historical = copy.deepcopy(desired)
    historical["fields"] = [
        field for field in historical["fields"] if field["name"] != "KP2BW_META"
    ]
    for field in historical["fields"]:
        if field["name"] == "KeePass:KP2BW_HISTORY:1":
            field["name"] = "KP2BW_HISTORY"
    historical["login"]["uris"] = [{"uri": "https://target.example", "match": None}]
    old_stamp = pre_history_content_signature(historical)
    for field in historical["fields"]:
        if field["name"] == "KP2BW_SYNC":
            field["value"] = old_stamp
    historical["login"]["uris"].append({"uri": "https://alias.example", "match": None})
    item_id = bw.create_item(historical)
    try:
        assert converter.convert(bw) == 0
        updated = vault.fresh().get_item(item_id)
        assert any(
            field["name"] == "KeePass:KP2BW_HISTORY:1" for field in updated["fields"]
        )
        assert not any(field["name"] == "KP2BW_HISTORY" for field in updated["fields"])
        records = records_from_fields(updated["fields"])
        assert len(records) == 1
        metadata_bytes = bw.get_attachment(
            item_id, next(iter(records.values())).attachment_id
        )
        assert json.loads(metadata_bytes) == {"tags": entry.tags}
        assert converter.convert(bw) == 0
        repeated = vault.fresh().get_item(item_id)
        assert repeated["revisionDate"] == updated["revisionDate"]
        assert "attachments" in repeated and "attachments" in updated
        assert repeated["attachments"] == updated["attachments"]
    finally:
        vault.delete(item_id)


def main() -> None:
    vault_main(run_metadata_test)


if __name__ == "__main__":
    main()
