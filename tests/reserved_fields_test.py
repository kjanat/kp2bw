"""Source namespace collisions stay lossless through conversion and maintenance."""

import copy
import tempfile
from pathlib import Path
from typing import cast

from lxml.etree import SubElement
from pykeepass import Entry, create_database

from kp2bw._item_sync import content_signature, stamp_content
from kp2bw._source_fields import source_field_name, source_field_origin
from kp2bw.bw_serve import BitwardenServeClient, item_kp2bw_id, item_kp2bw_sync
from kp2bw.bw_types import BwField, BwItemCreate, BwItemResponse
from kp2bw.convert import Converter


def append_field(entry: Entry, name: str, value: str, protected: bool) -> None:
    element = SubElement(entry._element, "String")
    SubElement(element, "Key").text = name
    SubElement(element, "Value", Protected=str(protected)).text = value


def converter() -> Converter:
    return Converter(
        keepass_file_path="synthetic.kdbx",
        keepass_password="synthetic",
        keepass_keyfile_path=None,
        bitwarden_password="synthetic",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
    )


class Client(BitwardenServeClient):
    def __init__(self, item: BwItemResponse) -> None:
        self.item = item
        self.updates: list[BwItemResponse] = []
        self._org_id = None
        self._collection_id = None

    def list_items(
        self,
        *,
        folder_id: str | None = None,
        organization_id: str | None = None,
        collection_id: str | None = None,
    ) -> list[BwItemResponse]:
        return [self.item]

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self.item = copy.deepcopy(item)
        self.updates.append(self.item)

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        pass


def reconcile(
    conv: Converter, client: Client, desired: BwItemCreate, identity: str
) -> str:
    outcome, _, _ = conv._reconcile_existing_item(
        client,
        client.item,
        None,
        desired,
        [],
        fixed_coll_id=None,
        kp_uuid=identity,
    )
    return outcome


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = create_database(
            Path(directory) / "source.kdbx", password="synthetic"
        )
        for with_metadata in (False, True):
            entry = database.add_entry(
                database.root_group, f"Reserved {with_metadata}", "user", "pw"
            )
            if with_metadata:
                entry.tags = ["tag"]
            source: list[tuple[str, str, bool]] = []
            for name in (
                "KP2BW_ID",
                "KP2BW_SYNC",
                "KP2BW_META",
                "KP2BW_FILE_user",
                "ordinary",
                "KeePass:KP2BW_ID:1",
            ):
                for protected in (False, True):
                    value = f"value {len(source)}"
                    source.append((name, value, protected))
                    append_field(entry, name, value, protected)
            append_field(entry, "KP2BW_ID_extra", "ordinary prefix", False)
            conv = converter()
            conv._add_bw_entry_to_entries_dict(entry)
            desired = next(iter(conv._entries.values()))[2]
            identity = entry.uuid.hex.upper()
            existing = cast(
                BwItemResponse,
                copy.deepcopy(desired) | {"id": "item-1", "revisionDate": "2026-01-01"},
            )
            assert item_kp2bw_id(existing) == identity
            assert item_kp2bw_sync(existing) == content_signature(existing)
            fields = {field["name"]: field for field in desired["fields"]}
            assert len(fields) == len(desired["fields"])
            counts: dict[str, int] = {}
            for name, value, protected in source:
                counts[name] = counts.get(name, 0) + 1
                escaped = source_field_name(name, counts[name])
                assert fields[escaped]["value"] == value
                assert fields[escaped]["type"] == int(protected)
                if escaped != name:
                    assert source_field_origin(escaped) == (name, counts[name])
            assert fields["KP2BW_ID_extra"]["value"] == "ordinary prefix"
            if not with_metadata:
                assert "KP2BW_META" not in fields
            client = Client(existing)
            assert reconcile(conv, client, desired, identity) == "skipped"
            assert not client.updates

            edited = copy.deepcopy(existing)
            edited["fields"][0]["value"] = "manual edit"
            assert reconcile(conv, Client(edited), desired, identity) == "protected"

            # Model older output: source ID/SYNC were overwritten; META survived
            # only when generated metadata did not replace it. Duplicates vanished.
            old = copy.deepcopy(existing)
            old_fields: list[BwField] = []
            for field in old["fields"]:
                origin = source_field_origin(field["name"])
                if origin:
                    name, occurrence = origin
                    if occurrence > 1 or name in {"KP2BW_ID", "KP2BW_SYNC"}:
                        continue
                    if name == "KP2BW_META" and with_metadata:
                        continue
                    field["name"] = name
                old_fields.append(field)
            old["fields"] = old_fields
            stamp_content(old)
            client = Client(old)
            assert reconcile(conv, client, desired, identity) == "updated"
            assert len(client.updates) == 1
            assert reconcile(conv, client, desired, identity) == "skipped"
            assert len(client.updates) == 1

            before = copy.deepcopy(client.item["fields"])
            result = client.strip_field_from_items("KP2BW_ID", "KP2BW_SYNC")
            assert result.stripped == 1
            assert client.item["fields"] == [
                field
                for field in before
                if field["name"] not in {"KP2BW_ID", "KP2BW_SYNC"}
            ]
            assert client.strip_field_from_items("KP2BW_ID", "KP2BW_SYNC").stripped == 0
            assert item_kp2bw_id(client.item) is None

        entry = database.add_entry(database.root_group, "OTP duplicate", "user", "pw")
        append_field(entry, "TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", False)
        append_field(entry, "TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ", False)
        conv = converter()
        conv._add_bw_entry_to_entries_dict(entry)
        item = next(iter(conv._entries.values()))[2]
        retained = next(
            field
            for field in item["fields"]
            if field["name"] == source_field_name("TimeOtp-Secret-Base32", 2)
        )
        assert retained["value"] == "GEZDGNBVGY3TQOJQ" and retained["type"] == 1
    print("reserved field collision tests passed")


if __name__ == "__main__":
    main()
