"""Lossless history archives and native previous-password extraction."""

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise

from lxml import etree
from pykeepass.entry import Entry

from .bw_types import BwPasswordHistory
from .exceptions import ConversionError


def _utc(value: datetime | None) -> datetime:
    if value is None:
        raise ConversionError("History timestamp is missing")
    if value.tzinfo is None:
        raise ConversionError("History timestamp has no timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime | None) -> str:
    return _utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def native_password_history(entry: Entry) -> list[BwPasswordHistory]:
    """Use the next password-changing version's mtime, not note-only edits.

    KeePass history contains snapshots from before a change. The following
    version's modification time is therefore the best available end of a
    password's use. Equal timestamps retain source XML order. Current values
    are excluded, and repeated older values retain their most recent use.
    """
    versions: list[Entry] = sorted(
        entry.history, key=lambda version: _utc(version.mtime)
    )
    if not versions:
        return []
    if _utc(versions[-1].mtime) > _utc(entry.mtime):
        raise ConversionError("Entry history is newer than the current entry")
    versions.append(entry)
    previous: list[BwPasswordHistory] = []
    seen = {entry.password or ""}
    for older, newer in reversed(list(pairwise(versions))):
        password = older.password or ""
        if password == (newer.password or "") or password in seen:
            continue
        seen.add(password)
        previous.append({"password": password, "lastUsedDate": _timestamp(newer.mtime)})
        if len(previous) == 5:
            break
    return previous


@dataclass(frozen=True)
class HistoryArchive:
    data: bytes
    records: int
    missing_binaries: int


def history_archive(entry: Entry, binaries: Sequence[bytes]) -> HistoryArchive | None:
    """Keep complete historical XML plus referenced binary contents in JSON.

    XML values have already been decrypted by PyKeePass. This output contains
    historical secrets, including fields marked Protected, and is intended
    only for the user's explicitly requested encrypted vault attachment.
    No wall-clock values enter the document, so unchanged source history
    produces identical bytes. Missing binaries retain their original reference.
    """
    history = entry.history
    if not history:
        return None
    records: list[dict[str, object]] = []
    references: set[int] = set()
    for version in history:
        for value in version._element.iterfind("Binary/Value"):
            ref = value.get("Ref")
            if ref is None:
                continue  # Inline data remains intact in the XML record.
            if not ref.isascii() or not ref.isdecimal():
                raise ConversionError(
                    "Historical attachment has an invalid binary reference"
                )
            references.add(int(ref))
        records.append({
            "created": _timestamp(version.ctime) if version.ctime is not None else None,
            "modified": _timestamp(version.mtime)
            if version.mtime is not None
            else None,
            "accessed": _timestamp(version.atime)
            if version.atime is not None
            else None,
            "xml": etree.tostring(
                version._element, encoding="unicode", with_tail=False
            ),
        })
    binary_records: dict[str, dict[str, object]] = {}
    missing = 0
    for ref in sorted(references):
        if ref >= len(binaries):
            binary_records[str(ref)] = {"available": False}
            missing += 1
            continue
        data = binaries[ref]
        binary_records[str(ref)] = {
            "available": True,
            "sha256": hashlib.sha256(data).hexdigest(),
            "base64": base64.b64encode(data).decode("ascii"),
        }
    document = {
        "format": "kp2bw-entry-history",
        "version": 1,
        "keepass_version": list(entry._kp.version) if entry._kp is not None else None,
        "xml_values": "decrypted",
        "entry_uuid": str(entry.uuid),
        "records": records,
        "binaries": binary_records,
    }
    return HistoryArchive(
        json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode(),
        len(records),
        missing,
    )
