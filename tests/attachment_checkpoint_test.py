"""Checkpoint scope, invalidation, process locking and crash-safe replacement."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

from convert_update_test import UpdateTestConverter, make_desired, make_existing

from kp2bw.attachment_resume import transaction_filename
from kp2bw.attachments import (
    FileRecord,
    fields_from_records,
    plan_attachments,
    source_file,
)
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemResponse
from kp2bw.checkpoint import (
    AttachmentCheckpoint,
    CheckpointRecord,
    CheckpointScope,
    metadata_digest,
)
from kp2bw.exceptions import ConversionError
from kp2bw.item_sync import stamp_content


def scope() -> CheckpointScope:
    return CheckpointScope(
        "https://synthetic.example", "account", "database", "org", "collection"
    )


def record() -> CheckpointRecord:
    return CheckpointRecord(
        entry_id="a" * 32,
        source_id="b" * 64,
        source_digest="c" * 64,
        source_size=42,
        item_id="item",
        name_digest="d" * 64,
        phase="mapped",
        attachment_id="file",
        remote_revision="revision",
        remote_metadata_digest="e" * 64,
    )


def child(mode: str, path: Path) -> None:
    try:
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            if mode == "locked":
                raise AssertionError("A second process acquired an active checkpoint")
            original_replace = os.replace

            def crash(source: str | Path, destination: str | Path) -> None:
                if mode == "after":
                    original_replace(source, destination)
                os._exit(91)

            with patch("kp2bw.checkpoint.os.replace", side_effect=crash):
                checkpoint.save(replace(record(), source_size=43))
    except ConversionError:
        if mode == "locked":
            sys.exit(23)
        raise


def subprocess_case(mode: str, path: Path) -> int:
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), mode, str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not result.stdout and not result.stderr, (
        "Unexpected checkpoint subprocess output"
    )
    return result.returncode


def reusable(saved: CheckpointRecord, observed: CheckpointRecord) -> bool:
    return saved.reusable(
        item_id=observed.item_id,
        attachment_id=observed.attachment_id or "",
        source_digest=observed.source_digest,
        source_size=observed.source_size,
        name_digest=observed.name_digest,
        revision=observed.remote_revision or "",
        remote_metadata_digest=observed.remote_metadata_digest or "",
    )


def main() -> None:
    saved = record()
    assert reusable(saved, saved)
    for phase in ("pending", "slot", "uploaded", "verified"):
        assert not reusable(
            CheckpointRecord.parse({
                **asdict(saved),
                "phase": phase,
                "before_ids": [],
            }),
            saved,
        )
    for key in (
        "item_id",
        "attachment_id",
        "source_digest",
        "source_size",
        "name_digest",
        "remote_revision",
        "remote_metadata_digest",
    ):
        changed = replace(saved, **{key: 43 if key == "source_size" else "f" * 64})
        assert not reusable(saved, changed)
    assert metadata_digest({"id": "file", "size": 42}) != metadata_digest({
        "id": "file",
        "size": 43,
    })
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "checkpoint.json"
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            assert checkpoint.records == {}
            checkpoint.save(saved)
            prior = path.read_bytes()
            assert subprocess_case("locked", path) == 23
            with patch(
                "kp2bw.checkpoint.os.replace",
                side_effect=OSError("synthetic write failure"),
            ):
                try:
                    checkpoint.save(replace(saved, source_size=43))
                except ConversionError:
                    pass
                else:
                    raise AssertionError(
                        "Failed atomic replacement was reported as saved"
                    )
            assert path.read_bytes() == prior
            assert checkpoint.records[saved.key] == saved
            try:
                checkpoint.save(replace(saved, entry_id="f" * 32))
            except ConversionError:
                pass
            else:
                raise AssertionError(
                    "One destination cannot be verified for two sources"
                )
        assert subprocess_case("before", path) == 91
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            assert checkpoint.records[saved.key] == saved
        assert subprocess_case("after", path) == 91
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            assert checkpoint.records[saved.key].source_size == 43
            checkpoint.save(saved)
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        for key in (
            "server",
            "account_id",
            "source_id",
            "organization_id",
            "collection_id",
        ):
            try:
                with AttachmentCheckpoint(path, replace(scope(), **{key: "different"})):
                    pass
            except ConversionError:
                pass
            else:
                raise AssertionError("A checkpoint crossed its migration scope")
            assert path.read_bytes() == prior
        for corrupt in (
            b"{",
            b"\xff",
            b"[]",
            json.dumps({
                "version": 1,
                "scope": scope().digest,
                "records": [{"password": "secret-must-not-be-stored"}],
            }).encode(),
        ):
            path.write_bytes(corrupt)
            with AttachmentCheckpoint(path, scope()) as checkpoint:
                assert not checkpoint.records
                checkpoint.save(saved)
            assert b"secret-must-not-be-stored" not in path.read_bytes()
            assert b"synthetic.example" not in path.read_bytes()
        with AttachmentCheckpoint(path, scope()) as checkpoint:
            assert checkpoint.records[saved.key] == saved
    print("attachment checkpoint atomicity and invalidation tests passed")
    check_planner_cache()
    check_failed_recovery_preserves_old_copy()


def check_planner_cache() -> None:
    source = source_file("original", "file.txt", 1, "file.txt", b"synthetic contents")
    associations = {
        source.source_id: FileRecord(
            "file", hashlib.sha256(b"file.txt").hexdigest(), source.digest
        )
    }
    item = make_existing(
        revisionDate="revision",
        fields=[
            {"name": "KP2BW_ID", "value": "a" * 32, "type": 0},
            *fields_from_records(associations),
        ],
        attachments=[
            {"id": "file", "fileName": "file.txt", "size": str(len(source.data))}
        ],
    )
    stamp_content(item)
    client = MagicMock(spec=BitwardenServeClient)

    def get_item(item_id: str) -> BwItemResponse:
        return copy.deepcopy(item)

    client.get_item.side_effect = get_item
    client.get_attachment.return_value = source.data
    bw = cast(BitwardenServeClient, client)
    converter = UpdateTestConverter()
    with (
        tempfile.TemporaryDirectory() as directory,
        AttachmentCheckpoint(Path(directory) / "cache.json", scope()) as checkpoint,
    ):
        converter.checkpoint = checkpoint

        def plan():
            return plan_attachments(
                [source],
                associations,
                [("file", "file.txt")],
                lambda attachment_id: converter.read_checkpoint_attachment(
                    bw, item, [source], associations, attachment_id
                ),
            )

        initial = plan()
        assert not initial.uploads
        converter.save_verified_checkpoint(bw, item["id"], initial)
        client.get_attachment.reset_mock()
        repeated = plan()
        assert not repeated.uploads
        converter.save_verified_checkpoint(bw, item["id"], repeated)
        client.get_attachment.assert_not_called()
        item["revisionDate"] = "remote-edit"
        assert not plan().uploads
        client.get_attachment.assert_called_once()
        client.get_attachment.return_value = b"remote edit"
        try:
            plan()
        except ConversionError:
            pass
        else:
            raise AssertionError(
                "A changed remote revision must recheck and protect remote bytes"
            )
        client.update_item.assert_not_called()
        client.upload_attachments.assert_not_called()
    print("attachment checkpoint skips unchanged downloads and protects remote edits")


def check_failed_recovery_preserves_old_copy() -> None:
    first = source_file("original", "first.txt", 1, "first.txt", b"replacement")
    second = source_file("original", "second.txt", 1, "second.txt", b"unchanged")
    old = FileRecord(
        "old",
        hashlib.sha256(b"first.txt").hexdigest(),
        hashlib.sha256(b"original").hexdigest(),
    )
    records = {
        first.source_id: old,
        second.source_id: FileRecord(
            "second", hashlib.sha256(b"second.txt").hexdigest(), second.digest
        ),
    }
    filename = transaction_filename(first, scope().digest, "a" * 32, "old")
    fields = [
        {"name": "KP2BW_ID", "value": "a" * 32, "type": 0},
        *fields_from_records(records),
    ]
    item = make_existing(
        fields=fields,
        attachments=[
            {"id": "old", "fileName": "first.txt"},
            {"id": "new", "fileName": filename},
            {"id": "second", "fileName": "second.txt"},
        ],
    )
    stamp_content(item)
    desired = make_desired(fields=[{"name": "KP2BW_ID", "value": "a" * 32, "type": 0}])
    bodies = {"old": b"original", "new": first.data, "second": b"destination edit"}
    client = MagicMock(spec=BitwardenServeClient)

    def get_item(item_id: str) -> BwItemResponse:
        assert item_id == item["id"]
        return copy.deepcopy(item)

    def get_attachment(item_id: str, attachment_id: str) -> bytes:
        assert item_id == item["id"]
        return bodies[attachment_id]

    def update_item(item_id: str, payload: BwItemResponse) -> None:
        assert item_id == item["id"]
        item.update(copy.deepcopy(payload))

    client.get_item.side_effect = get_item
    client.get_attachment.side_effect = get_attachment
    client.update_item.side_effect = update_item
    bw = cast(BitwardenServeClient, client)
    converter = UpdateTestConverter()
    with (
        tempfile.TemporaryDirectory() as directory,
        AttachmentCheckpoint(
            Path(directory) / "checkpoint.json", scope()
        ) as checkpoint,
    ):
        converter.checkpoint = checkpoint
        checkpoint.save(
            CheckpointRecord(
                entry_id="a" * 32,
                source_id=first.source_id,
                source_digest=first.digest,
                source_size=len(first.data),
                item_id=item["id"],
                name_digest=hashlib.sha256(filename.encode()).hexdigest(),
                phase="uploaded",
                attachment_id="new",
                previous_attachment_id="old",
                previous_digest=old.digest,
                previous_name_digest=old.name_digest,
                before_ids=("old", "second"),
            )
        )
        outcome, uploads, _ = converter.reconcile(
            bw, item, None, desired, [first, second], fixed_coll_id=None
        )
        assert outcome == "failed" and not uploads
        assert not converter.checkpoint_cleanup
        assert item["id"] not in converter.attachment_plans
        try:
            converter.delete_checkpoint_copy(bw, item["id"], "old", filename)
        except ConversionError:
            pass
        else:
            raise AssertionError(
                "An unpersisted recovered association authorized deletion"
            )
        client.delete_attachment.assert_not_called()
        bodies["second"] = second.data
        outcome, uploads, _ = converter.reconcile(
            bw, item, None, desired, [first, second], fixed_coll_id=None
        )
        assert outcome != "failed" and not uploads
        assert converter.checkpoint_cleanup == [(item["id"], "old", filename)]
        plan = converter.attachment_plans[item["id"]]
        converter.persist_attachment_plan(bw, item["id"], plan, set())
        converter.delete_checkpoint_copy(bw, item["id"], "old", filename)
        client.delete_attachment.assert_called_once_with(item["id"], "old")
    print(
        "recovered attachments retain old copies until all associations are persisted"
    )


if __name__ == "__main__":
    if len(sys.argv) == 3:
        child(sys.argv[1], Path(sys.argv[2]))
    else:
        main()
