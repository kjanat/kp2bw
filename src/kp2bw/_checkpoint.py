"""Atomic, scope-bound attachment verification metadata; never vault contents."""

import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal, Self, cast

from .exceptions import ConversionError

logger = logging.getLogger(__name__)
type Phase = Literal["pending", "slot", "uploaded", "verified", "mapped"]
_PHASES = {"pending", "slot", "uploaded", "verified", "mapped"}
_DIGEST = re.compile(r"[0-9a-f]{64}")


def metadata_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True)
class CheckpointScope:
    server: str
    account_id: str
    source_id: str
    organization_id: str | None = None
    collection_id: str | None = None

    @property
    def digest(self) -> str:
        if not self.server or not self.account_id or not self.source_id:
            raise ConversionError(
                "Checkpoint requires a known server, account and source"
            )
        return metadata_digest(asdict(self))


@dataclass(frozen=True)
class CheckpointRecord:
    entry_id: str
    source_id: str
    source_digest: str
    source_size: int
    item_id: str
    name_digest: str
    phase: Phase
    attachment_id: str | None = None
    remote_revision: str | None = None
    remote_metadata_digest: str | None = None
    previous_attachment_id: str | None = None
    previous_digest: str | None = None
    previous_name_digest: str | None = None
    before_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"[0-9a-fA-F]{32}", self.entry_id)
            or not all(
                _DIGEST.fullmatch(v)
                for v in (self.source_id, self.source_digest, self.name_digest)
            )
            or type(self.source_size) is not int
            or self.source_size < 0
            or not self.item_id
            or self.phase not in _PHASES
            or len(set(self.before_ids)) != len(self.before_ids)
        ):
            raise ConversionError("Invalid attachment checkpoint record")
        if self.phase == "slot" and not self.attachment_id:
            raise ConversionError(
                "Checkpoint slot requires a destination attachment ID"
            )
        if self.previous_attachment_id is not None and (
            self.previous_digest is None
            or not _DIGEST.fullmatch(self.previous_digest)
            or self.previous_name_digest is None
            or not _DIGEST.fullmatch(self.previous_name_digest)
        ):
            raise ConversionError(
                "Checkpoint replacement requires the previous file's verified hashes"
            )
        if self.remote_metadata_digest is not None and not _DIGEST.fullmatch(
            self.remote_metadata_digest
        ):
            raise ConversionError("Invalid checkpoint remote metadata digest")
        if self.phase in {"verified", "mapped"} and not (
            self.attachment_id and self.remote_revision and self.remote_metadata_digest
        ):
            raise ConversionError(
                "Verified checkpoint requires a remote identity and revision"
            )

    @property
    def key(self) -> str:
        return self.entry_id.upper() + ":" + self.source_id

    def reusable(
        self,
        *,
        item_id: str,
        attachment_id: str,
        source_digest: str,
        source_size: int,
        name_digest: str,
        revision: str,
        remote_metadata_digest: str,
    ) -> bool:
        return self.phase == "mapped" and (
            self.item_id,
            self.attachment_id,
            self.source_digest,
            self.source_size,
            self.name_digest,
            self.remote_revision,
            self.remote_metadata_digest,
        ) == (
            item_id,
            attachment_id,
            source_digest,
            source_size,
            name_digest,
            revision,
            remote_metadata_digest,
        )

    @classmethod
    def parse(cls, value: object) -> Self:
        if not isinstance(value, dict):
            raise ConversionError("Invalid attachment checkpoint record")
        row = cast(dict[str, object], value)
        strings = {
            "entry_id",
            "source_id",
            "source_digest",
            "item_id",
            "name_digest",
            "phase",
        }
        optional = {
            "attachment_id",
            "remote_revision",
            "remote_metadata_digest",
            "previous_attachment_id",
            "previous_digest",
            "previous_name_digest",
        }
        if (
            set(row) != strings | optional | {"source_size", "before_ids"}
            or any(not isinstance(row[key], str) for key in strings)
            or any(
                row[key] is not None and not isinstance(row[key], str)
                for key in optional
            )
            or type(row["source_size"]) is not int
            or not isinstance(row["before_ids"], list)
            or any(
                not isinstance(v, str) or not v
                for v in cast(list[object], row["before_ids"])
            )
        ):
            raise ConversionError("Invalid attachment checkpoint schema")
        return cls(
            entry_id=cast(str, row["entry_id"]),
            source_id=cast(str, row["source_id"]),
            source_digest=cast(str, row["source_digest"]),
            source_size=row["source_size"],
            item_id=cast(str, row["item_id"]),
            name_digest=cast(str, row["name_digest"]),
            phase=cast(Phase, row["phase"]),
            attachment_id=cast(str | None, row["attachment_id"]),
            remote_revision=cast(str | None, row["remote_revision"]),
            remote_metadata_digest=cast(str | None, row["remote_metadata_digest"]),
            previous_attachment_id=cast(str | None, row["previous_attachment_id"]),
            previous_digest=cast(str | None, row["previous_digest"]),
            previous_name_digest=cast(str | None, row["previous_name_digest"]),
            before_ids=tuple(cast(list[str], row["before_ids"])),
        )


class AttachmentCheckpoint:
    """Hold a process lock for the migration and atomically replace snapshots."""

    def __init__(self, path: Path, scope: CheckpointScope) -> None:
        self.path = path
        self.scope_digest = scope.digest
        self.records: dict[str, CheckpointRecord] = {}
        self._lock: int | None = None

    def __enter__(self) -> Self:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            lock_path = self.path.with_name(self.path.name + ".lock")
            fd = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
        except OSError:
            raise ConversionError(
                "Cannot open the attachment checkpoint lock"
            ) from None
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(fd).st_size == 0:
                    _ = os.write(fd, b"\0")
                _ = os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise ConversionError(
                "Attachment checkpoint is already in use or cannot be locked"
            ) from None
        self._lock = fd
        try:
            self._load()
        except OSError:
            self.close()
            raise ConversionError("Cannot read the attachment checkpoint") from None
        except ConversionError:
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def _load(self) -> None:
        try:
            value: object = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except UnicodeError, ValueError:
            logger.warning(
                "Corrupt attachment checkpoint ignored; remote files will be verified again"
            )
            return
        if not isinstance(value, dict):
            logger.warning(
                "Invalid attachment checkpoint ignored; remote files will be verified again"
            )
            return
        data = cast(dict[str, object], value)
        if data.get("scope") is not None and data["scope"] != self.scope_digest:
            raise ConversionError(
                "Attachment checkpoint belongs to a different account, server or source scope"
            )
        try:
            if (
                set(data) != {"version", "scope", "records"}
                or type(data["version"]) is not int
                or data["version"] != 1
                or data["scope"] != self.scope_digest
                or not isinstance(data["records"], list)
            ):
                raise ConversionError("Invalid attachment checkpoint schema")
            records = [
                CheckpointRecord.parse(row)
                for row in cast(list[object], data["records"])
            ]
            loaded = {record.key: record for record in records}
            if len(loaded) != len(records):
                raise ConversionError("Duplicate checkpoint source identities")
            self._check_destinations(loaded)
        except ConversionError:
            logger.warning(
                "Invalid attachment checkpoint ignored; remote files will be verified again"
            )
            return
        self.records = loaded

    def save(self, record: CheckpointRecord) -> None:
        self.save_many([record])

    def save_many(self, updates: Sequence[CheckpointRecord]) -> None:
        if self._lock is None:
            raise ConversionError("Attachment checkpoint must be locked before writing")
        records = {**self.records, **{record.key: record for record in updates}}
        self._check_destinations(records)
        try:
            self._write(records)
        except OSError:
            raise ConversionError(
                "Could not atomically save the attachment checkpoint"
            ) from None
        self.records = records

    @staticmethod
    def _check_destinations(records: dict[str, CheckpointRecord]) -> None:
        destinations = [
            (record.item_id, record.attachment_id)
            for record in records.values()
            if record.attachment_id is not None
        ]
        if len(set(destinations)) != len(destinations):
            raise ConversionError("Ambiguous checkpoint destination identities")

    def _write(self, records: dict[str, CheckpointRecord]) -> None:
        data = {
            "version": 1,
            "scope": self.scope_digest,
            "records": [asdict(records[key]) for key in sorted(records)],
        }
        descriptor, filename = tempfile.mkstemp(
            prefix="." + self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(filename)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory = os.open(
                    self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
