"""Attachment source identities, persistent destination IDs and collision-free names."""

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import cast

from .bw_types import BwField
from .exceptions import ConversionError

ATTACHMENT_FIELD_PREFIX = "KP2BW_FILE_"
HEX_ID = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SourceFile:
    kind: str
    source_id: str
    original_name: str
    filename: str
    data: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def source_file(
    kind: str, key: str, occurrence: int, filename: str, data: bytes
) -> SourceFile:
    """Duplicate originals use their occurrence within that name in source XML.

    KeePass attachment references have no immutable UUID. Their binary IDs are
    storage indexes that can change on a save, so they are not source identity.
    """
    identity = json.dumps([kind, key, occurrence], ensure_ascii=True).encode()
    return SourceFile(
        kind, hashlib.sha256(identity).hexdigest(), filename, filename, data
    )


@dataclass(frozen=True)
class FileRecord:
    attachment_id: str
    name_digest: str
    digest: str


def records_from_fields(fields: Sequence[BwField]) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    used_ids: set[str] = set()
    for field in fields:
        name = field.get("name") or ""
        if not name.startswith(ATTACHMENT_FIELD_PREFIX):
            continue
        source_id = name[len(ATTACHMENT_FIELD_PREFIX) :]
        try:
            value = json.loads(field.get("value") or "")
        except (ValueError, TypeError) as exc:
            raise ConversionError("Invalid attachment association metadata") from exc
        if not isinstance(value, dict):
            raise ConversionError("Invalid attachment association metadata")
        values = cast(dict[str, object], value)
        attachment_id, name_digest, digest = (
            values.get(key) for key in ("id", "name", "sha256")
        )
        if (
            not HEX_ID.fullmatch(source_id)
            or source_id in records
            or set(values) != {"id", "name", "sha256"}
            or not isinstance(attachment_id, str)
            or not attachment_id
            or not isinstance(name_digest, str)
            or not HEX_ID.fullmatch(name_digest)
            or not isinstance(digest, str)
            or not HEX_ID.fullmatch(digest)
            or attachment_id in used_ids
        ):
            raise ConversionError(
                "Invalid or duplicate attachment association metadata"
            )
        records[source_id] = FileRecord(attachment_id, name_digest, digest)
        used_ids.add(attachment_id)
    return records


def is_record_field(field: BwField) -> bool:
    """Recognize our schema without claiming arbitrary source lookalikes."""
    try:
        return bool(records_from_fields([field]))
    except ConversionError:
        return False


def fields_from_records(records: dict[str, FileRecord]) -> list[BwField]:
    return [
        BwField(
            name=ATTACHMENT_FIELD_PREFIX + source_id,
            type=0,
            value=json.dumps(
                {
                    "id": record.attachment_id,
                    "name": record.name_digest,
                    "sha256": record.digest,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        for source_id, record in sorted(records.items())
    ]


@dataclass
class AttachmentPlan:
    sources: list[SourceFile]
    records: dict[str, FileRecord]
    previous_records: dict[str, FileRecord]
    uploads: list[SourceFile]
    stale: dict[str, str]


def plan_attachments(
    sources: Sequence[SourceFile],
    records: dict[str, FileRecord],
    remote: Sequence[tuple[str, str]],
    read: Callable[[str], bytes],
) -> AttachmentPlan:
    """Bind by recorded ID; adopt legacy names only when association is unique.

    No mutation occurs here. An ambiguous legacy item or externally modified
    mapped file fails before any attachment upload or deletion can happen.
    """
    if len({source.source_id for source in sources}) != len(sources):
        raise ConversionError("Duplicate source attachment identities")
    by_name: dict[str, list[str]] = defaultdict(list)
    by_id = dict(remote)
    if len(by_id) != len(remote):
        raise ConversionError("Duplicate destination attachment IDs")
    for attachment_id, name in remote:
        by_name[name].append(attachment_id)
    desired_counts = Counter(s.original_name for s in sources)
    contents: dict[str, bytes] = {}

    def content(attachment_id: str) -> bytes:
        if attachment_id not in contents:
            contents[attachment_id] = read(attachment_id)
        return contents[attachment_id]

    def allocated_name_pattern(source: SourceFile) -> re.Pattern[str]:
        suffix = PurePosixPath(source.original_name).suffix
        stem = source.original_name[: -len(suffix)] if suffix else source.original_name
        return re.compile(
            re.escape(f"{stem} (kp2bw-{source.source_id[:16]}")
            + r"(?:-[1-9][0-9]*)?"
            + re.escape(f"){suffix}")
        )

    associated = dict(records)
    claimed = {record.attachment_id for record in records.values()}
    if not records:
        # Source-specific collision names identify pending first-import uploads.
        # Claim these before matching unsuffixed legacy names, including when
        # several source files have identical names and bytes.
        for source in sources:
            pattern = allocated_name_pattern(source)
            pending = [
                (attachment_id, name)
                for attachment_id, name in remote
                if attachment_id not in claimed
                and name not in desired_counts
                and pattern.fullmatch(name)
                and content(attachment_id) == source.data
            ]
            if len(pending) > 1:
                raise ConversionError(
                    "Ambiguous pending attachment association; no files were changed"
                )
            if pending:
                attachment_id, name = pending[0]
                associated[source.source_id] = FileRecord(
                    attachment_id,
                    hashlib.sha256(name.encode()).hexdigest(),
                    source.digest,
                )
                claimed.add(attachment_id)
        # Legacy adoption: matching bytes can distinguish different same-named
        # files, but identical duplicates have no recoverable source identity.
        for source in sources:
            if source.source_id in associated:
                continue
            candidates = [
                attachment_id
                for attachment_id in by_name.get(source.original_name, [])
                if attachment_id not in claimed
            ]
            exact = [
                attachment_id
                for attachment_id in candidates
                if content(attachment_id) == source.data
            ]
            same_sources = sum(
                s.original_name == source.original_name
                and s.data == source.data
                and s.source_id not in associated
                for s in sources
            )
            if len(exact) == 1 and same_sources == 1:
                attachment_id = exact[0]
            elif len(candidates) == 1 and desired_counts[source.original_name] == 1:
                attachment_id = candidates[0]
            elif candidates:
                raise ConversionError(
                    "Ambiguous legacy attachment association; no files were changed"
                )
            else:
                continue
            if attachment_id in claimed:
                raise ConversionError(
                    "A destination attachment matches multiple source files"
                )
            associated[source.source_id] = FileRecord(
                attachment_id,
                hashlib.sha256(source.original_name.encode()).hexdigest(),
                hashlib.sha256(content(attachment_id)).hexdigest(),
            )
            claimed.add(attachment_id)

    # Existing associations keep their allocated names when another source is
    # added. Reserve all source names too so a suffix never steals another file's
    # original name. Originals take precedence over generated files on first run
    # through the caller's source ordering.
    reserved = {name for _, name in remote} | {s.original_name for s in sources}
    allocated: set[str] = set()
    planned: list[SourceFile] = []
    uploads: list[SourceFile] = []
    stale: dict[str, str] = {}

    def available_name(source: SourceFile) -> str:
        path = PurePosixPath(source.original_name)
        suffix = path.suffix
        stem = source.original_name[: -len(suffix)] if suffix else source.original_name
        index = 0
        while True:
            extra = f"-{index}" if index else ""
            filename = f"{stem} (kp2bw-{source.source_id[:16]}{extra}){suffix}"
            if filename not in reserved and filename not in allocated:
                return filename
            index += 1

    for source in sources:
        record = associated.get(source.source_id)
        if record is not None:
            name = by_id.get(record.attachment_id)
            if (
                name is None
                or hashlib.sha256(name.encode()).hexdigest() != record.name_digest
            ):
                raise ConversionError(
                    "A mapped attachment was removed or renamed; no files were changed"
                )
            current = content(record.attachment_id)
            if hashlib.sha256(current).hexdigest() != record.digest:
                raise ConversionError(
                    "A mapped attachment was edited in the destination; no files were changed"
                )
            filename = available_name(source) if name in allocated else name
            selected = replace(source, filename=filename)
            if current != source.data or filename != name:
                candidates = [
                    attachment_id
                    for attachment_id in by_name.get(filename, [])
                    if attachment_id not in claimed
                    and content(attachment_id) == source.data
                ]
                if len(candidates) > 1:
                    raise ConversionError(
                        "Pending replacement has ambiguous attachment IDs; no files were changed"
                    )
                if candidates:
                    attachment_id = candidates[0]
                    associated[source.source_id] = FileRecord(
                        attachment_id,
                        hashlib.sha256(filename.encode()).hexdigest(),
                        source.digest,
                    )
                    claimed.add(attachment_id)
                else:
                    uploads.append(selected)
                stale[source.source_id] = record.attachment_id
        else:
            filename = source.original_name
            if filename in allocated or filename in by_name:
                filename = available_name(source)
            allocated_pattern = allocated_name_pattern(source)
            candidates = [
                (attachment_id, name)
                for attachment_id, name in remote
                if attachment_id not in claimed
                and name not in allocated
                and (
                    (name == source.original_name and desired_counts[name] == 1)
                    or (
                        allocated_pattern.fullmatch(name) and name not in desired_counts
                    )
                )
                and content(attachment_id) == source.data
            ]
            if len(candidates) > 1:
                raise ConversionError(
                    "Pending upload has ambiguous attachment IDs; no files were changed"
                )
            if candidates:
                attachment_id, filename = candidates[0]
                associated[source.source_id] = FileRecord(
                    attachment_id,
                    hashlib.sha256(filename.encode()).hexdigest(),
                    source.digest,
                )
                claimed.add(attachment_id)
            selected = replace(source, filename=filename)
            if not candidates:
                uploads.append(selected)
        planned.append(selected)
        allocated.add(selected.filename)
    return AttachmentPlan(planned, associated, dict(records), uploads, stale)
