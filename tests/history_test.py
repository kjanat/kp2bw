"""Historical password transitions and recoverable, deterministic archives."""

import base64
import copy
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from convert_update_test import UpdateTestConverter, _make_desired, _make_existing
from lxml import etree
from pykeepass import PyKeePass, create_database

from kp2bw._attachments import SourceFile
from kp2bw._history import (
    apply_native_history,
    history_archive,
    native_password_history,
)
from kp2bw._item_sync import (
    content_signature,
    pre_fido2_content_signature,
    stamp_content,
    sync_stamp_matches,
)
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse, BwPasswordHistory
from kp2bw.convert import Converter
from kp2bw.exceptions import (
    BitwardenClientError,
    BitwardenServeExitedError,
    ConversionError,
    HistoryConversionError,
)


def check_native_updates() -> None:
    source: list[BwPasswordHistory] = [
        {"password": "old source", "lastUsedDate": "2020-01-01T00:00:00Z"}
    ]
    remote = cast(
        BwItemResponse,
        {
            "id": "item",
            "type": 1,
            "fields": [],
            "login": {"password": "current"},
            "passwordHistory": [
                {"password": "destination only", "lastUsedDate": "2019-01-01T00:00:00Z"}
            ],
        },
    )
    item = copy.deepcopy(remote)
    apply_native_history(item, source, existing=remote)
    assert (
        next(field for field in item["fields"] if field["name"] == "KP2BW_HISTORY")[
            "type"
        ]
        == 1
    )
    assert [record["password"] for record in item.get("passwordHistory") or []] == [
        "old source",
        "destination only",
    ]
    repeated = copy.deepcopy(item)
    apply_native_history(repeated, source, existing=item)
    assert repeated == item
    stamp_content(item)
    stamp = content_signature(item)
    assert sync_stamp_matches(item, stamp)
    altered = copy.deepcopy(item)
    altered_history = altered.get("passwordHistory")
    assert altered_history is not None
    altered_history[0]["lastUsedDate"] = "2020-01-01T00:00:00.000+00:00"
    assert sync_stamp_matches(altered, stamp), "Equivalent dates must not appear edited"
    altered_history[0]["password"] = "manual change"
    assert not sync_stamp_matches(altered, stamp)
    for native_type in (2, 3, 4, 5):
        native = copy.deepcopy(item)
        native["type"] = native_type
        native_stamp = content_signature(native)
        history = native.get("passwordHistory")
        assert history is not None
        history[0]["password"] = "manual change"
        assert not sync_stamp_matches(native, native_stamp), (
            "Native item history edits must remain protected"
        )
    newer: list[BwPasswordHistory] = [
        {"password": "new source", "lastUsedDate": "2021-01-01T00:00:00Z"}
    ]
    desired = copy.deepcopy(item)
    apply_native_history(desired, newer, existing=item)
    assert [record["password"] for record in desired.get("passwordHistory") or []] == [
        "new source",
        "destination only",
    ]
    full = copy.deepcopy(remote)
    full["passwordHistory"] = [
        {"password": str(i), "lastUsedDate": "2019-01-01T00:00:00Z"} for i in range(5)
    ]
    before = copy.deepcopy(full)
    try:
        apply_native_history(full, source, existing=before)
    except ConversionError:
        pass
    else:
        raise AssertionError("Unrelated native history was evicted")
    assert full == before

    client = object.__new__(BitwardenServeClient)
    client._history_updates_supported = False
    with (
        patch.object(BitwardenServeClient, "get_item", return_value=item),
        patch.object(BitwardenServeClient, "_request") as request,
    ):
        try:
            client.update_item("item", desired)
        except BitwardenClientError as exc:
            assert "No item update was sent" in str(exc)
        else:
            raise AssertionError("Unsupported native history update was sent")
        request.assert_not_called()
    client._history_updates_supported = True
    with (
        patch.object(BitwardenServeClient, "get_item", return_value=desired),
        patch.object(BitwardenServeClient, "_request") as request,
    ):
        client.update_item("item", desired)
        assert [call.args[0] for call in request.call_args_list] == ["PUT", "POST"]
    with (
        patch.object(BitwardenServeClient, "get_item", return_value=item),
        patch.object(BitwardenServeClient, "_request") as request,
    ):
        try:
            client.update_item("item", desired)
        except BitwardenClientError as exc:
            assert "could not be verified" in str(exc)
        else:
            raise AssertionError("Lost native history update was accepted")
        assert sum(call.args[0] == "PUT" for call in request.call_args_list) == 1

    existing = _make_existing(revisionDate="revision-1")
    apply_native_history(existing, source)
    stamp_content(existing)
    desired_item = _make_desired()
    apply_native_history(desired_item, newer)
    converter = UpdateTestConverter()
    bw = MagicMock(spec=BitwardenServeClient)
    bw.get_item.return_value = copy.deepcopy(existing)
    outcome, _, _ = converter.reconcile(
        cast(BitwardenServeClient, bw),
        existing,
        None,
        desired_item,
        [],
        fixed_coll_id=None,
    )
    assert outcome == "updated"
    bw.update_item.assert_not_called()
    assert (
        bw.update_item_if_revision.call_args.kwargs["expected_revision"] == "revision-1"
    )
    bw.reset_mock()
    raced = copy.deepcopy(existing)
    raced["notes"] = "concurrent destination edit"
    bw.get_item.return_value = raced
    outcome, _, _ = converter.reconcile(
        cast(BitwardenServeClient, bw),
        existing,
        None,
        desired_item,
        [],
        fixed_coll_id=None,
    )
    assert outcome == "protected"
    bw.update_item_if_revision.assert_not_called()
    bw.update_item.assert_not_called()


def main() -> None:
    check_native_updates()
    check_review_regressions()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "history.kdbx"
        db = create_database(path, password="test")
        entry = db.add_entry(db.root_group, "History", "user", "first")
        assert native_password_history(entry) == []
        assert history_archive(entry, db.binaries) is None

        entry.ctime = datetime(2010, 1, 1, tzinfo=UTC)
        entry.atime = datetime(2011, 1, 1, tzinfo=UTC)
        old_bytes = b"historical attachment\x00\xff"
        ref = db.add_binary(old_bytes)
        attachment = entry.add_attachment(ref, "historical.dat")
        entry.notes = "old notes"
        entry.set_custom_property("KP2BW_HISTORY", "source data")
        entry.set_custom_property(
            "protected old value", "historical secret", protect=True
        )
        versions = [
            "first",
            "first",
            "second",
            "third",
            "second",
            "fourth",
            "fifth",
            "sixth",
            "seventh",
        ]
        for day, password in enumerate(versions, start=1):
            entry.password = password
            entry.mtime = datetime(2020, 1, day, tzinfo=UTC)
            entry.save_history()
        entry.password = "current"
        entry.mtime = datetime(2020, 1, 10, tzinfo=UTC)
        entry.notes = "current notes"
        entry.delete_attachment(attachment)
        entry.set_custom_property("protected old value", "current secret", protect=True)
        expected = [
            {"password": password, "lastUsedDate": f"2020-01-{day:02d}T00:00:00.000Z"}
            for password, day in [
                ("seventh", 10),
                ("sixth", 9),
                ("fifth", 8),
                ("fourth", 7),
                ("second", 6),
            ]
        ]
        assert native_password_history(entry) == expected
        archive = history_archive(entry, db.binaries)
        assert (
            archive is not None
            and archive.records == 9
            and archive.missing_binaries == 0
        )
        assert history_archive(entry, db.binaries) == archive
        document = json.loads(archive.data)
        assert document["entry_uuid"] == str(entry.uuid)
        recovered = document["binaries"][str(ref)]
        assert base64.b64decode(recovered["base64"]) == old_bytes
        assert recovered["sha256"] == hashlib.sha256(old_bytes).hexdigest()
        record = document["records"][0]
        assert record["created"] == "2010-01-01T00:00:00.000Z"
        assert record["modified"] == "2020-01-01T00:00:00.000Z"
        root = etree.fromstring(record["xml"].encode())
        fields = {
            field.findtext("Key"): field.find("Value")
            for field in root.findall("String")
        }
        note = fields["Notes"]
        protected = fields["protected old value"]
        reference = root.find("Binary/Value")
        assert note is not None and protected is not None and reference is not None
        assert note.text == "old notes"
        assert protected.get("Protected") == "True"
        assert protected.text == "historical secret"
        assert reference.get("Ref") == str(ref)

        # A saved/reopened database must preserve values, chronology and bytes.
        db.save()
        reopened = PyKeePass(path, password="test")
        restored = reopened.entries[0]
        assert native_password_history(restored) == expected
        reopened_archive = history_archive(restored, reopened.binaries)
        assert reopened_archive is not None
        assert history_archive(restored, reopened.binaries) == reopened_archive
        reopened_document = json.loads(reopened_archive.data)
        assert reopened_document["binaries"] == document["binaries"]
        assert len(reopened_document["records"]) == len(document["records"])
        for before, after in zip(
            document["records"], reopened_document["records"], strict=True
        ):
            before_xml, after_xml = before.pop("xml"), after.pop("xml")
            assert before == after
            parser = etree.XMLParser(remove_blank_text=True)
            assert etree.tostring(
                etree.fromstring(before_xml.encode(), parser)
            ) == etree.tostring(etree.fromstring(after_xml.encode(), parser))

        # Reusing an old password must not place the current password in history.
        entry.password = "second"
        result = native_password_history(entry)
        assert all(record["password"] != "second" for record in result)
        assert len({record["password"] for record in result}) == len(result) == 5

        # Note-only changes do not become artificial password-change dates.
        small = db.add_entry(db.root_group, "Notes", "user", "a")
        for day in (1, 2):
            small.mtime = datetime(2020, 2, day, tzinfo=UTC)
            small.notes = f"notes {day}"
            small.save_history()
        small.password = "b"
        small.mtime = datetime(2020, 2, 3, tzinfo=UTC)
        assert native_password_history(small) == [
            {"password": "a", "lastUsedDate": "2020-02-03T00:00:00.000Z"}
        ]
        small.mtime = datetime(2019, 1, 1, tzinfo=UTC)
        try:
            native_password_history(small)
        except ConversionError:
            pass
        else:
            raise AssertionError("History newer than current entry was accepted")

        # Missing original bytes are explicit, with the complete reference kept.
        incomplete = history_archive(entry, [])
        assert incomplete is not None and incomplete.missing_binaries == 1
        assert json.loads(incomplete.data)["binaries"][str(ref)] == {"available": False}

        # Generated history uses the attachment identity planner, so a real
        # history.json survives alongside the generated archive across reruns.
        small.mtime = datetime(2020, 2, 3, tzinfo=UTC)
        entry.add_attachment(db.add_binary(b"original user file"), "history.json")
        db.save()
        converter = Converter(
            str(path),
            "test",
            None,
            "test",
            None,
            None,
            False,
            0,
            None,
            archive_history=True,
        )
        converter._load_keepass_data()
        key = str(entry.uuid).replace("-", "").upper()
        converted = converter._unpack_entry(converter._entries[key])[2]
        assert (
            next(
                field["value"]
                for field in converted["fields"]
                if field["name"] == "KeePass:KP2BW_HISTORY:1"
            )
            == "source data"
        )
        sources = converter._unpack_entry(converter._entries[key])[3]
        files = [source for source in sources if isinstance(source, SourceFile)]
        assert len(files) == 2
        assert len({source.filename for source in files}) == 2
        original = next(source for source in files if source.kind == "original")
        generated = next(source for source in files if source.kind == "history")
        assert (
            original.filename == "history.json"
            and original.data == b"original user file"
        )
        assert json.loads(generated.data)["entry_uuid"] == str(entry.uuid)
        converter._load_keepass_data()
        assert converter._unpack_entry(converter._entries[key])[3] == sources
        normal = Converter(str(path), "test", None, "test", None, None, False, 0, None)
        normal._load_keepass_data()
        normal_sources = normal._unpack_entry(normal._entries[key])[3]
        assert len(normal_sources) == 1

        small.history[0].password = f"{{REF:P@I:{entry.uuid.hex}}}"
        try:
            native_password_history(small)
        except ConversionError:
            pass
        else:
            raise AssertionError("Historical REF was emitted as a literal password")
        db.save()
        archive_only = Converter(
            str(path),
            "test",
            None,
            "test",
            None,
            None,
            False,
            0,
            None,
            archive_history=True,
            migrate_password_history=False,
        )
        archive_only._load_keepass_data()
        for value in archive_only._entries.values():
            assert "passwordHistory" not in archive_only._unpack_entry(value)[2]
    print("password history extraction and archive round trips passed")


def check_review_regressions() -> None:
    source: list[BwPasswordHistory] = [
        {"password": "previous", "lastUsedDate": "2020-01-01T00:00:00Z"}
    ]
    existing = _make_existing(revisionDate="before")
    desired = _make_desired()
    apply_native_history(desired, source)
    bw = MagicMock(spec=BitwardenServeClient)
    for field in ("favorite", "folderId"):
        raced = copy.deepcopy(existing)
        raced["revisionDate"] = "after"
        if field == "favorite":
            raced["favorite"] = False
        else:
            raced["folderId"] = "moved"
        bw.get_item.return_value = raced
        outcome, _, _ = UpdateTestConverter().reconcile(
            cast(BitwardenServeClient, bw),
            existing,
            None,
            desired,
            [],
            fixed_coll_id=None,
        )
        assert outcome == "protected"
        bw.update_item_if_revision.assert_not_called()
    bw.get_item.return_value = copy.deepcopy(existing)
    bw.update_item_if_revision.side_effect = BitwardenServeExitedError(
        "synthetic serve exit"
    )
    try:
        UpdateTestConverter().reconcile(
            cast(BitwardenServeClient, bw),
            existing,
            None,
            desired,
            [],
            fixed_coll_id=None,
        )
    except BitwardenServeExitedError:
        pass
    else:
        raise AssertionError("Fatal serve exit became a recoverable history failure")
    bw = MagicMock(spec=BitwardenServeClient)
    existing["passwordHistory"] = [
        {"password": str(i), "lastUsedDate": "2019-01-01T00:00:00Z"} for i in range(5)
    ]
    desired["collectionIds"] = ["new-collection"]
    outcome, _, _ = UpdateTestConverter(update_existing=False).reconcile(
        cast(BitwardenServeClient, bw), existing, None, desired, [], fixed_coll_id=None
    )
    assert outcome == "collection"
    assert (
        bw.update_item.call_args.args[1]["passwordHistory"]
        == existing["passwordHistory"]
    )
    bw.update_item_if_revision.assert_not_called()
    for native in (False, True):
        legacy = _make_existing()
        legacy["fields"].append({
            "name": "KP2BW_HISTORY",
            "value": "ordinary source value",
            "type": 0,
        })
        legacy["fields"].append({
            "name": "KP2BW_SYNC",
            "value": pre_fido2_content_signature(legacy),
            "type": 0,
        })
        requested = _make_desired()
        requested["fields"].append({
            "name": "KeePass:KP2BW_HISTORY:1",
            "value": "ordinary source value",
            "type": 0,
        })
        if native:
            apply_native_history(requested, source)
        client = MagicMock(spec=BitwardenServeClient)
        client.get_item.return_value = copy.deepcopy(legacy)
        outcome, _, _ = UpdateTestConverter().reconcile(
            cast(BitwardenServeClient, client),
            legacy,
            None,
            requested,
            [],
            fixed_coll_id=None,
        )
        assert outcome == "updated"
        write = client.update_item_if_revision if native else client.update_item
        payload = write.call_args.args[1]
        assert {
            "name": "KeePass:KP2BW_HISTORY:1",
            "value": "ordinary source value",
            "type": 0,
        } in payload["fields"]
        assert any(f["name"] == "KP2BW_HISTORY" for f in payload["fields"]) is native
        legacy["fields"][1]["value"] = "destination edit"
        client.reset_mock()
        outcome, _, _ = UpdateTestConverter().reconcile(
            cast(BitwardenServeClient, client),
            legacy,
            None,
            requested,
            [],
            fixed_coll_id=None,
        )
        assert outcome == "protected"
        client.update_item.assert_not_called()
        client.update_item_if_revision.assert_not_called()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ref-history.kdbx"
        db = create_database(path, password="synthetic")
        target = db.add_entry(db.root_group, "Target", "user", "pw")
        alias = db.add_entry(
            db.root_group,
            "Alias",
            f"{{REF:U@I:{target.uuid.hex}}}",
            f"{{REF:P@I:{target.uuid.hex}}}",
        )
        alias.save_history()
        alias.password = "changed"
        db.save()
        converter = Converter(
            str(path), "synthetic", None, "", None, None, False, 999, None
        )
        with patch.object(converter, "_create_bitwarden_items_for_entries") as writes:
            try:
                converter.convert()
            except HistoryConversionError as exc:
                assert "--no-password-history" in str(exc)
            else:
                raise AssertionError("REF history failure silently omitted an entry")
            writes.assert_not_called()


if __name__ == "__main__":
    main()
