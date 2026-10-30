"""Interrupted upload reconciliation excludes old copies and other writers."""

import copy
import hashlib
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import httpx
from convert_update_test import UpdateTestConverter, _make_existing

from kp2bw._attachment_resume import inspect_pending_upload, transaction_filename
from kp2bw._attachments import AttachmentPlan, FileRecord, source_file
from kp2bw._checkpoint import AttachmentCheckpoint, CheckpointRecord, CheckpointScope
from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwAttachment, BwItemResponse
from kp2bw.exceptions import (
    BitwardenAttachmentMissingError,
    BitwardenHttpError,
    ConversionError,
)


def main() -> None:
    for message, missing in (
        ("A 404 error occurred while downloading the attachment.", True),
        ("Vaultwarden request failed (HTTP 404).", True),
        ("Not found.", False),
        ("Attachment ID was not found.", False),
        ("Vaultwarden request failed (HTTP 403).", False),
        ("Attachment download failed.", False),
    ):
        client = object.__new__(BitwardenServeClient)

        def respond(_request: httpx.Request, message: str = message) -> httpx.Response:
            return httpx.Response(400, json={"success": False, "message": message})

        client._http = httpx.Client(
            base_url="http://localhost", transport=httpx.MockTransport(respond)
        )
        try:
            client.get_attachment("item", "file")
        except BitwardenHttpError as exc:
            assert isinstance(exc, BitwardenAttachmentMissingError) is missing
            assert message not in str(exc), (
                "Raw CLI errors must not leak through checkpoint diagnostics"
            )
        else:
            raise AssertionError("A failed download was treated as file bytes")
        finally:
            client._http.close()
    source = source_file("original", "key.bin", 1, "key.bin", b"replacement")
    scope = "a" * 64
    name = transaction_filename(source, scope, "b" * 32, "old")
    assert name == transaction_filename(source, scope, "B" * 32, "old")
    assert name != transaction_filename(source, scope, "b" * 32, None)
    assert name != transaction_filename(
        replace(source, data=b"changed"), scope, "b" * 32, "old"
    )
    record = CheckpointRecord(
        entry_id="b" * 32,
        source_id=source.source_id,
        source_digest=source.digest,
        source_size=len(source.data),
        item_id="item",
        name_digest=hashlib.sha256(name.encode()).hexdigest(),
        phase="pending",
        previous_attachment_id="old",
        previous_digest=hashlib.sha256(b"old").hexdigest(),
        previous_name_digest=hashlib.sha256(b"key.bin").hexdigest(),
        before_ids=("old", "unrelated"),
    )
    remote: list[BwAttachment] = [
        {"id": "old", "fileName": "key.bin"},
        {"id": "unrelated", "fileName": name},
        {"id": "other-writer", "fileName": "key.bin"},
        {"id": "orphan", "fileName": name},
        {"id": "complete", "fileName": name},
        {"id": "late-retry", "fileName": name},
    ]
    reads: list[str] = []

    def read(attachment_id: str) -> bytes | None:
        reads.append(attachment_id)
        assert attachment_id not in {"old", "unrelated", "other-writer"}
        return None if attachment_id == "orphan" else source.data

    decision = inspect_pending_upload(source, record, scope, remote, read)
    assert decision.attachment_id == "complete"
    assert decision.orphan_ids == ("orphan",)
    assert decision.duplicate_ids == ("late-retry",)
    assert set(reads) == {"orphan", "complete", "late-retry"}
    selected = replace(record, phase="uploaded", attachment_id="late-retry")
    assert (
        inspect_pending_upload(source, selected, scope, remote, read).attachment_id
        == "late-retry"
    )
    assert (
        inspect_pending_upload(source, record, scope, remote[:3], read).attachment_id
        is None
    )
    for changed in (
        replace(source, data=b"different"),
        replace(source, source_id="f" * 64),
    ):
        try:
            inspect_pending_upload(changed, record, scope, remote, read)
        except ConversionError:
            pass
        else:
            raise AssertionError(
                "Changed source must not authorize cleanup of a pending upload"
            )
    try:
        inspect_pending_upload(source, record, scope, remote, lambda _: b"remote edit")
    except ConversionError:
        pass
    else:
        raise AssertionError("Unexpected remote bytes must be preserved")
    print("attachment transaction recovery decisions passed")
    check_cleanup_protection()
    check_missing_checkpoint_adoption()


def check_missing_checkpoint_adoption() -> None:
    source = source_file("original", "key.bin", 1, "key.bin", b"replacement")
    scope = CheckpointScope("https://synthetic.example", "account", "database")
    name = transaction_filename(source, scope.digest, "b" * 32, "old")
    previous = FileRecord(
        "old",
        hashlib.sha256(b"key.bin").hexdigest(),
        hashlib.sha256(b"old").hexdigest(),
    )
    for condition in ("complete", "edited", "ambiguous"):
        item = _make_existing(
            revisionDate="revision",
            fields=[{"name": "KP2BW_ID", "value": "b" * 32, "type": 0}],
            attachments=[
                {"id": "old", "fileName": "key.bin"},
                {"id": "new", "fileName": name},
            ],
        )
        if condition == "ambiguous":
            attachments = item.get("attachments")
            assert attachments is not None
            attachments.append({"id": "duplicate", "fileName": name})
        plan = AttachmentPlan(
            [source],
            {source.source_id: previous},
            {source.source_id: previous},
            [source],
            {source.source_id: "old"},
        )
        client = MagicMock(spec=BitwardenServeClient)
        client.get_attachment.return_value = (
            b"remote edit" if condition == "edited" else source.data
        )
        converter = UpdateTestConverter()
        with (
            tempfile.TemporaryDirectory() as directory,
            AttachmentCheckpoint(Path(directory) / "cache.json", scope) as checkpoint,
        ):
            converter._checkpoint = checkpoint
            try:
                converter._prepare_checkpoint_uploads(
                    cast(BitwardenServeClient, client), item, plan
                )
            except ConversionError:
                assert condition != "complete"
                assert not checkpoint.records
                assert plan.uploads == [source]
            else:
                assert condition == "complete"
                assert not plan.uploads
                assert plan.records[source.source_id].attachment_id == "new"
                saved = next(iter(checkpoint.records.values()))
                assert saved.phase == "verified"
                assert saved.previous_digest == previous.digest
                assert saved.previous_attachment_id == "old"
                assert saved.before_ids == ("old",)
            client.delete_attachment.assert_not_called()
            client.upload_attachments.assert_not_called()
    print("missing checkpoint adopts only unique verified transaction bytes")


def check_cleanup_protection() -> None:
    source = source_file("original", "key.bin", 1, "key.bin", b"replacement")
    scope = CheckpointScope("https://synthetic.example", "account", "database")
    name = transaction_filename(source, scope.digest, "b" * 32, "old")
    pending = CheckpointRecord(
        entry_id="b" * 32,
        source_id=source.source_id,
        source_digest=source.digest,
        source_size=len(source.data),
        item_id="item-1",
        name_digest=hashlib.sha256(name.encode()).hexdigest(),
        phase="verified",
        attachment_id="new",
        remote_revision="revision",
        remote_metadata_digest="f" * 64,
        previous_attachment_id="old",
        previous_digest=hashlib.sha256(b"old").hexdigest(),
        previous_name_digest=hashlib.sha256(b"key.bin").hexdigest(),
        before_ids=("old",),
    )
    for condition in ("unchanged", "edited", "renamed", "concurrent"):
        item = _make_existing(
            revisionDate="revision",
            fields=[{"name": "KP2BW_ID", "value": "b" * 32, "type": 0}],
            attachments=[
                {
                    "id": "old",
                    "fileName": "renamed" if condition == "renamed" else "key.bin",
                },
                {"id": "new", "fileName": name},
            ],
        )
        client = MagicMock(spec=BitwardenServeClient)

        def get_item(_item_id: str, item: BwItemResponse = item) -> BwItemResponse:
            return copy.deepcopy(item)

        def get_attachment(
            _item_id: str,
            attachment_id: str,
            condition: str = condition,
            item: BwItemResponse = item,
        ) -> bytes:
            if attachment_id == "new":
                return source.data
            if condition == "concurrent":
                item["revisionDate"] = "changed"
            return b"edited" if condition == "edited" else b"old"

        client.get_item.side_effect = get_item
        client.get_attachment.side_effect = get_attachment
        bw = cast(BitwardenServeClient, client)
        converter = UpdateTestConverter()
        with (
            tempfile.TemporaryDirectory() as directory,
            AttachmentCheckpoint(Path(directory) / "cache.json", scope) as checkpoint,
        ):
            checkpoint.save(pending)
            converter._checkpoint = checkpoint
            try:
                converter._delete_checkpoint_copy(bw, "item-1", "old", name)
            except ConversionError:
                assert condition != "unchanged"
                client.delete_attachment.assert_not_called()
            else:
                assert condition == "unchanged"
                client.delete_attachment.assert_called_once_with("item-1", "old")
            if condition in {"edited", "renamed"}:
                associations = {
                    source.source_id: FileRecord(
                        "old",
                        pending.previous_name_digest or "",
                        pending.previous_digest or "",
                    )
                }
                try:
                    converter._recover_checkpoint_uploads(
                        bw, item, [source], associations
                    )
                except ConversionError:
                    pass
                else:
                    raise AssertionError(
                        "Recovery must preserve edits to the previous attachment"
                    )
                client.delete_attachment.assert_not_called()
    print("checkpoint cleanup preserves remote and concurrent edits")


if __name__ == "__main__":
    main()
