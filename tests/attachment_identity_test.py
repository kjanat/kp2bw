"""Attachment identities survive filename collisions and content replacement."""

import copy
import hashlib
from dataclasses import replace
from typing import cast
from unittest.mock import MagicMock

from convert_update_test import (
    FakeBw,
    UpdateTestConverter,
    as_bw,
    make_desired,
    make_existing,
)

from kp2bw.attachments import (
    FileRecord,
    fields_from_records,
    plan_attachments,
    records_from_fields,
    source_file,
)
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.exceptions import (
    BitwardenClientError,
    BitwardenServeExitedError,
    ConversionError,
)
from kp2bw.item_sync import stamp_content
from kp2bw.source_fields import source_field_name, source_field_origin


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
    cached = make_existing(
        fields=fields_from_records(records),
        attachments=[
            {"id": "old-id", "fileName": "file.txt"},
            {"id": "new-id", "fileName": "file.txt"},
        ],
    )
    stamp_content(cached)
    remote = copy.deepcopy(cached)
    client = MagicMock(spec=BitwardenServeClient)

    def update(item_id: str, item: BwItemResponse) -> None:
        nonlocal remote
        if failure != "lost-write":
            remote = copy.deepcopy(item)

    def sync(*, force: bool = False) -> None:
        nonlocal cached
        assert force, "Normal sync may skip the revision already observed by the CLI"
        if failure == "sync":
            raise BitwardenClientError("synthetic sync failure")
        cached = copy.deepcopy(remote)

    def get_item(item_id: str) -> BwItemResponse:
        return copy.deepcopy(cached)

    client.get_item.side_effect = get_item
    client.get_attachment.return_value = b"new"
    client.update_item.side_effect = update
    client.sync.side_effect = sync
    converter = UpdateTestConverter()
    try:
        converter.persist_attachment_plan(
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
        existing = make_existing(attachments=[{"id": "file", "fileName": "file.txt"}])
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
                make_desired(),
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
    for absent in (True, False):
        raw: dict[str, object] = dict(make_existing())
        if absent:
            raw.pop("fields")
        else:
            raw["fields"] = None
        client = FakeBw()
        desired = make_desired()
        desired["fields"].append({
            "name": "KP2BW_ID",
            "value": "legacy-source",
            "type": 0,
        })
        outcome, _, _ = UpdateTestConverter().reconcile(
            as_bw(client),
            cast(BwItemResponse, raw),
            None,
            desired,
            [],
            fixed_coll_id=None,
            force_update=True,
        )
        assert outcome == "updated"
        assert any(
            field["name"] == "KP2BW_ID" for field in client.updates[0][1]["fields"]
        )
        assert any(
            field["name"] == "KP2BW_SYNC" for field in client.updates[0][1]["fields"]
        )
    existing = make_existing(
        collectionIds=["old"],
        fields=fields_from_records({
            "a" * 64: FileRecord("attachment", "b" * 64, "c" * 64)
        }),
    )
    stamp_content(existing)
    existing["notes"] = "preserve destination edit"
    client = FakeBw(fail_get_attachment=True)
    outcome, uploads, stale = UpdateTestConverter(update_existing=False).reconcile(
        as_bw(client),
        existing,
        None,
        make_desired(collectionIds=["new"]),
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
    recovered_initial = plan_attachments(sources, {}, remote, data.__getitem__)
    assert not recovered_initial.uploads and not recovered_initial.stale
    assert recovered_initial.records == records
    for missing in (sources[0], sources[4]):
        # Includes distinct and identical bytes: the other source already has
        # its own recorded ID, so only this unsuffixed upload remains unclaimed.
        partial = {
            key: value for key, value in records.items() if key != missing.source_id
        }
        for _ in range(2):
            recovered_partial = plan_attachments(
                sources, partial, remote, data.__getitem__
            )
            assert not recovered_partial.uploads and not recovered_partial.stale
            assert recovered_partial.records == records
            assert recovered_partial.previous_records == partial
    ambiguous_partial = {
        key: value
        for key, value in records.items()
        if key not in {s.source_id for s in sources[4:]}
    }
    try:
        plan_attachments(sources, ambiguous_partial, remote, data.__getitem__)
    except ConversionError:
        pass
    else:
        raise AssertionError("Identical unassociated sources were guessed")
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
    # Verification can fail after a collision rename uploads, while persistence
    # records both old IDs. Repeated retries must recover that same upload.
    pending_name = legacy.uploads[0].filename
    legacy_remote = [("0", "notes.txt"), ("1", "notes.txt")]
    data["collision-pending"] = sources[1].data
    pending_remote = [*legacy_remote, ("collision-pending", pending_name)]
    for _ in range(2):
        retry = plan_attachments(
            sources[:2], legacy.records, pending_remote, data.__getitem__
        )
        assert not retry.uploads
        assert retry.sources[1].filename == pending_name
        assert retry.records[sources[1].source_id].attachment_id == "collision-pending"
        assert retry.previous_records == legacy.records
        assert retry.stale == {sources[1].source_id: "1"}
    data["collision-duplicate"] = sources[1].data
    try:
        plan_attachments(
            sources[:2],
            legacy.records,
            [
                *pending_remote,
                ("collision-duplicate", pending_name.replace(").txt", "-1).txt")),
            ],
            data.__getitem__,
        )
    except ConversionError:
        pass
    else:
        raise AssertionError("Ambiguous collision replacement was accepted")
    data["collision-pending"] = b"unrelated bytes"
    retry = plan_attachments(
        sources[:2], legacy.records, pending_remote, data.__getitem__
    )
    assert len(retry.uploads) == 1 and retry.uploads[0].filename != pending_name
    assert retry.records == legacy.records
    # One uniquely matching legacy file is safe to adopt; the missing source
    # needs its own upload, without replacing or deleting the matched file.
    partial_legacy = plan_attachments(
        sources[:2], {}, [("0", "notes.txt")], data.__getitem__
    )
    assert set(partial_legacy.records) == {sources[0].source_id}
    assert partial_legacy.records[sources[0].source_id].attachment_id == "0"
    assert [source.source_id for source in partial_legacy.uploads] == [
        sources[1].source_id
    ]
    assert partial_legacy.uploads[0].filename != "notes.txt"
    assert not partial_legacy.stale
    data["unknown-legacy"] = b"bytes matching neither source"
    for legacy_sources, legacy_remote in (
        (sources[4:], [("4", "same.bin"), ("5", "same.bin")]),
        (sources[:2], [("unknown-legacy", "notes.txt")]),
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
