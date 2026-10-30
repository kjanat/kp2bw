"""Attachment identities survive filename collisions and content replacement."""

import copy
import hashlib
from dataclasses import replace
from typing import cast
from unittest.mock import MagicMock

from convert_update_test import (
    FakeBw,
    UpdateTestConverter,
    _as_bw,
    _make_desired,
    _make_existing,
)

from kp2bw._attachments import (
    FileRecord,
    fields_from_records,
    plan_attachments,
    records_from_fields,
    source_file,
)
from kp2bw._item_sync import stamp_content
from kp2bw._source_fields import source_field_name, source_field_origin
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.exceptions import (
    BitwardenClientError,
    BitwardenServeExitedError,
    ConversionError,
)


def check_persisted_mapping(failure: str | None) -> None:
    original = source_file("original", "file.txt", 1, "file.txt", b"old")
    replacement = replace(original, data=b"new")
    records = {
        original.source_id: FileRecord(
            "old-id", hashlib.sha256(b"file.txt").hexdigest(), original.digest
        )
    }
    plan = plan_attachments(
        [replacement], records, [("old-id", "file.txt")], lambda _: b"old"
    )
    cached = _make_existing(
        fields=fields_from_records(records),
        attachments=[
            {"id": "old-id", "fileName": "file.txt"},
            {"id": "new-id", "fileName": "file.txt"},
        ],
    )
    stamp_content(cached)
    remote = copy.deepcopy(cached)
    client = MagicMock(spec=BitwardenServeClient)

    def update(_item_id: str, item: BwItemResponse) -> None:
        nonlocal remote
        if failure != "lost-write":
            remote = copy.deepcopy(item)

    def sync(*, force: bool = False) -> None:
        nonlocal cached
        assert force, "Normal sync may skip the revision already observed by the CLI"
        if failure == "sync":
            raise BitwardenClientError("synthetic sync failure")
        cached = copy.deepcopy(remote)

    def get_item(_item_id: str) -> BwItemResponse:
        return copy.deepcopy(cached)

    client.get_item.side_effect = get_item
    client.get_attachment.return_value = b"new"
    client.update_item.side_effect = update
    client.sync.side_effect = sync
    converter = UpdateTestConverter()
    try:
        converter._persist_attachment_plan(
            cast(BitwardenServeClient, client), "item", plan, set()
        )
    except (BitwardenClientError, ConversionError):
        assert failure is not None
    else:
        assert failure is None
        assert (
            records_from_fields(cached["fields"])[original.source_id].attachment_id
            == "new-id"
        )
    client.update_item.assert_called_once()
    client.sync.assert_called_once_with(force=True)
    client.delete_attachment.assert_not_called()


def check_fatal_attachment_read() -> None:
    source = source_file("original", "file.txt", 1, "file.txt", b"data")
    for operation in ("get_item", "get_attachment"):
        existing = _make_existing(attachments=[{"id": "file", "fileName": "file.txt"}])
        client = MagicMock(spec=BitwardenServeClient)
        client.get_item.return_value = existing
        getattr(client, operation).side_effect = BitwardenServeExitedError(
            "serve exited"
        )
        try:
            UpdateTestConverter().reconcile(
                cast(BitwardenServeClient, client),
                existing,
                None,
                _make_desired(),
                [source],
                fixed_coll_id=None,
            )
        except BitwardenServeExitedError:
            pass
        else:
            raise AssertionError(f"Fatal {operation} failure was swallowed")
        client.upload_attachments.assert_not_called()
        client.delete_attachment.assert_not_called()


def main() -> None:
    check_fatal_attachment_read()
    existing = _make_existing(
        collectionIds=["old"],
        fields=fields_from_records({
            "a" * 64: FileRecord("attachment", "b" * 64, "c" * 64)
        }),
    )
    stamp_content(existing)
    existing["notes"] = "preserve destination edit"
    client = FakeBw(fail_get_attachment=True)
    outcome, uploads, stale = UpdateTestConverter(update_existing=False).reconcile(
        _as_bw(client),
        existing,
        None,
        _make_desired(collectionIds=["new"]),
        [],
        fixed_coll_id=None,
    )
    assert outcome == "collection" and not uploads and not stale
    assert client.updates[0][1]["notes"] == "preserve destination edit"
    assert client.updates[0][1]["fields"] == existing["fields"]
    assert client.updates[0][1]["collectionIds"] == ["old", "new"]
    for failure in (None, "sync", "lost-write"):
        check_persisted_mapping(failure)
    reserved = "KP2BW_FILE_" + "0" * 64
    escaped = source_field_name(reserved)
    assert escaped != reserved and source_field_origin(escaped) == (reserved, 1)
    sources = [
        source_file("original", "notes.txt", 1, "notes.txt", b"original one"),
        source_file("original", "notes.txt", 2, "notes.txt", b"original two"),
        source_file("notes", "", 1, "notes.txt", b"generated notes"),
        source_file("field", "notes", 1, "notes.txt", b"custom notes"),
        source_file("original", "same.bin", 1, "same.bin", b"identical"),
        source_file("original", "same.bin", 2, "same.bin", b"identical"),
    ]
    plan = plan_attachments(sources, {}, [], lambda _: b"")
    assert len({source.filename for source in plan.sources}) == len(sources)
    assert plan.sources[0].filename == "notes.txt"
    assert plan == plan_attachments(sources, {}, [], lambda _: b"")
    records: dict[str, FileRecord] = {}
    remote: list[tuple[str, str]] = []
    data: dict[str, bytes] = {}
    for index, source in enumerate(plan.sources):
        attachment_id = str(index)
        data[attachment_id] = source.data
        remote.append((attachment_id, source.filename))
        records[source.source_id] = FileRecord(
            attachment_id,
            hashlib.sha256(source.filename.encode()).hexdigest(),
            source.digest,
        )
    fields = fields_from_records(records)
    assert records_from_fields(fields) == records
    try:
        records_from_fields([*fields, fields[0]])
    except ConversionError:
        pass
    else:
        raise AssertionError("Duplicate association accepted")
    unchanged = plan_attachments(sources, records, remote, data.__getitem__)
    assert not unchanged.uploads and not unchanged.stale
    edited = list(sources)
    edited[1] = replace(edited[1], data=b"replaced second original")
    changed = plan_attachments(edited, records, remote, data.__getitem__)
    assert len(changed.uploads) == 1
    assert changed.stale == {sources[1].source_id: "1"}
    assert changed.uploads[0].filename == plan.sources[1].filename
    replacement_id = "pending-replacement"
    data[replacement_id] = edited[1].data
    pending_remote = [*remote, (replacement_id, changed.uploads[0].filename)]
    recovered = plan_attachments(edited, records, pending_remote, data.__getitem__)
    assert not recovered.uploads
    assert recovered.records[edited[1].source_id].attachment_id == replacement_id
    assert recovered.previous_records == records
    assert recovered.stale == {edited[1].source_id: "1"}
    # A second identical candidate must not trigger yet another upload.
    data["ambiguous"] = edited[1].data
    try:
        plan_attachments(
            edited,
            records,
            [*pending_remote, ("ambiguous", changed.uploads[0].filename)],
            data.__getitem__,
        )
    except ConversionError:
        pass
    else:
        raise AssertionError("Ambiguous pending replacement was accepted")
    # New sources reuse acknowledged uploads even if saving the association failed.
    added = source_file("original", "added.txt", 1, "added.txt", b"added")
    for collision in (False, True):
        before = [*remote, *(([("unrelated", "added.txt")]) if collision else [])]
        data["unrelated"] = b"unrelated"
        first = plan_attachments([*sources, added], records, before, data.__getitem__)
        assert len(first.uploads) == 1
        pending_name = first.uploads[0].filename
        data["new-source"] = added.data
        pending = [*before, ("new-source", pending_name)]
        for _ in range(2):
            retry = plan_attachments(
                [*sources, added], records, pending, data.__getitem__
            )
            assert not retry.uploads and not retry.stale
            assert retry.records[added.source_id].attachment_id == "new-source"
            assert retry.previous_records == records
        data["duplicate-new-source"] = added.data
        try:
            plan_attachments(
                [*sources, added],
                records,
                [*pending, ("duplicate-new-source", pending_name)],
                data.__getitem__,
            )
        except ConversionError:
            pass
        else:
            raise AssertionError("Ambiguous new-source upload was accepted")
    # Different legacy bytes establish a unique match, even with duplicate names.
    legacy = plan_attachments(
        sources[:2], {}, [("0", "notes.txt"), ("1", "notes.txt")], data.__getitem__
    )
    assert legacy.records[sources[0].source_id].attachment_id == "0"
    assert legacy.records[sources[1].source_id].attachment_id == "1"
    assert len({source.filename for source in legacy.sources}) == 2
    assert legacy.stale == {sources[1].source_id: "1"}
    for legacy_sources, legacy_remote in (
        (sources[4:], [("4", "same.bin"), ("5", "same.bin")]),
        (sources[:2], [("0", "notes.txt")]),
    ):
        try:
            plan_attachments(legacy_sources, {}, legacy_remote, data.__getitem__)
        except ConversionError:
            pass
        else:
            raise AssertionError("Ambiguous legacy files accepted")
    # A destination edit must never be deleted as a stale source copy.
    data["1"] = b"manual destination edit"
    try:
        plan_attachments(edited, records, remote, data.__getitem__)
    except ConversionError:
        pass
    else:
        raise AssertionError("Destination edit was overwritten")
    print("attachment identity, allocation and legacy association tests passed")


if __name__ == "__main__":
    main()
