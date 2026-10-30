"""Attachment identities survive filename collisions and content replacement."""

import hashlib
from dataclasses import replace

from kp2bw._attachments import (
    FileRecord,
    fields_from_records,
    plan_attachments,
    records_from_fields,
    source_file,
)
from kp2bw._source_fields import source_field_name, source_field_origin
from kp2bw.exceptions import ConversionError


def main() -> None:
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
