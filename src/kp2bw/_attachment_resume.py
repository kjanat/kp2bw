"""Reconcile uncertain uploads by transaction identity, never by name alone."""

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from ._attachments import SourceFile
from ._checkpoint import CheckpointRecord, metadata_digest
from .bw_types import BwAttachment
from .exceptions import ConversionError


def transaction_filename(
    source: SourceFile,
    scope_digest: str,
    entry_id: str,
    previous_id: str | None,
) -> str:
    """Bind a visible suffix to this source, contents, scope and replacement.

    This remains stable across retries and can be predicted by a read-only
    preview. A filename collision with another writer's ordinary upload cannot
    authorize deletion of that writer's incomplete attachment slot.
    """
    token = metadata_digest([
        scope_digest,
        entry_id.upper(),
        source.source_id,
        source.digest,
        previous_id,
    ])[:32]
    extension = PurePosixPath(source.original_name).suffix
    stem = (
        source.original_name[: -len(extension)] if extension else source.original_name
    )
    return f"{stem} (kp2bw-{token}){extension}"


@dataclass(frozen=True)
class ResumeDecision:
    attachment_id: str | None
    orphan_ids: tuple[str, ...] = ()
    duplicate_ids: tuple[str, ...] = ()


def inspect_pending_upload(
    source: SourceFile,
    record: CheckpointRecord,
    scope_digest: str,
    remote: Sequence[BwAttachment],
    read: Callable[[str], bytes | None],
) -> ResumeDecision:
    """Read every transaction candidate before authorizing any cleanup.

    ``None`` means a confirmed missing attachment body, not a timeout or an
    authentication error. The caller must recheck the item revision before
    deleting slots. A previous attachment and every pre-upload ID are excluded.
    """
    if (
        source.source_id != record.source_id
        or source.digest != record.source_digest
        or len(source.data) != record.source_size
    ):
        raise ConversionError("Source changed while its attachment upload was pending")
    filename = transaction_filename(
        source, scope_digest, record.entry_id, record.previous_attachment_id
    )
    if hashlib.sha256(filename.encode()).hexdigest() != record.name_digest:
        raise ConversionError("Pending attachment has no valid transaction identity")
    if len({attachment["id"] for attachment in remote}) != len(remote):
        raise ConversionError("Duplicate attachment IDs prevent checkpoint recovery")
    candidates = [
        attachment["id"]
        for attachment in remote
        if attachment["fileName"] == filename
        and attachment["id"] not in record.before_ids
        and attachment["id"] != record.previous_attachment_id
    ]
    if record.attachment_id is not None and any(
        attachment["id"] == record.attachment_id and attachment["fileName"] != filename
        for attachment in remote
    ):
        raise ConversionError("Pending attachment was renamed in the destination")
    verified: list[str] = []
    orphaned: list[str] = []
    for attachment_id in candidates:
        contents = read(attachment_id)
        if contents is None:
            orphaned.append(attachment_id)
        elif contents == source.data:
            verified.append(attachment_id)
        else:
            raise ConversionError(
                "Pending attachment has different remote contents; preserving it"
            )
    selected = (
        record.attachment_id
        if record.attachment_id in verified
        else min(verified)
        if verified
        else None
    )
    return ResumeDecision(
        selected, tuple(orphaned), tuple(item for item in verified if item != selected)
    )
