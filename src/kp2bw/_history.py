"""Lossless history archives and native previous-password extraction."""

import base64
import copy
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import cast

from lxml import etree
from pykeepass.entry import Entry

from .bw_types import BwField, BwItemCreate, BwItemResponse, BwPasswordHistory
from .exceptions import HistoryConversionError

HISTORY_FIELD_NAME = "KP2BW_HISTORY"


def has_managed_history(item: BwItemCreate | BwItemResponse) -> bool:
    return any(
        field.get("name") == HISTORY_FIELD_NAME for field in item.get("fields") or []
    )


def _history_time(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return _timestamp(datetime.fromisoformat(value))
    except (ValueError, TypeError) as exc:
        raise HistoryConversionError(
            "Password history contains an invalid timestamp"
        ) from exc


def history_signature(
    item: BwItemCreate | BwItemResponse,
) -> list[tuple[str, str | None]]:
    """Normalize equivalent UTC timestamp spellings without exposing values."""
    return [
        (record["password"], _history_time(record["lastUsedDate"]))
        for record in item.get("passwordHistory") or []
    ]


def _record_hash(record: BwPasswordHistory) -> str:
    value = (record["password"], _history_time(record["lastUsedDate"]))
    return hashlib.sha256(json.dumps(value, ensure_ascii=True).encode()).hexdigest()


def _managed_records(item: BwItemCreate | BwItemResponse) -> set[str]:
    fields = [
        field
        for field in item.get("fields") or []
        if field.get("name") == HISTORY_FIELD_NAME
    ]
    if not fields:
        return set()
    if (
        len(fields) != 1
        or fields[0].get("type") != 1
        or fields[0].get("linkedId") is not None
    ):
        raise HistoryConversionError("Ambiguous password history metadata")
    try:
        metadata = json.loads(fields[0].get("value") or "")
    except ValueError as exc:
        raise HistoryConversionError("Invalid password history metadata") from exc
    if not isinstance(metadata, dict):
        raise HistoryConversionError("Invalid password history metadata")
    metadata = cast(dict[str, object], metadata)
    if (
        set(metadata) != {"version", "records"}
        or type(metadata["version"]) is not int
        or metadata["version"] != 1
    ):
        raise HistoryConversionError("Unknown password history metadata")
    records = metadata["records"]
    if not isinstance(records, list):
        raise HistoryConversionError("Invalid password history record identities")
    records = cast(list[object], records)
    if len(records) > 5 or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        for value in records
    ):
        raise HistoryConversionError("Invalid password history record identities")
    return {value for value in records if isinstance(value, str)}


def apply_native_history(
    item: BwItemCreate | BwItemResponse,
    source: list[BwPasswordHistory],
    *,
    existing: BwItemResponse | None = None,
) -> None:
    """Replace only previously imported records; retain unrelated vault history.

    Native history has five slots. Refuse a merge which cannot fit rather than
    silently evicting an unrelated destination record. The opt-in archive has
    no such historical-record limit.
    """
    old_managed: set[str] = (
        _managed_records(existing) if existing is not None else set()
    )
    unrelated = (
        [
            copy.copy(record)
            for record in (existing.get("passwordHistory") or [])
            if _record_hash(record) not in old_managed
        ]
        if existing is not None
        else []
    )
    unrelated_passwords = {record["password"] for record in unrelated}
    imported = [
        copy.copy(record)
        for record in source
        if record["password"] not in unrelated_passwords
    ]
    if len(imported) + len(unrelated) > 5:
        raise HistoryConversionError(
            "Native history has only five slots; preserving unrelated Bitwarden history"
        )
    item["passwordHistory"] = [*imported, *unrelated]
    fields: list[BwField] = [
        field
        for field in item.get("fields") or []
        if field.get("name") != HISTORY_FIELD_NAME
    ]
    fields.append({
        "name": HISTORY_FIELD_NAME,
        "type": 1,
        "value": json.dumps(
            {"version": 1, "records": [_record_hash(record) for record in imported]},
            sort_keys=True,
        ),
    })
    item["fields"] = fields


def imported_history_count(item: BwItemCreate | BwItemResponse) -> int:
    """Count source records represented natively, excluding unrelated history."""
    return len(_managed_records(item))


def _utc(value: datetime | None) -> datetime:
    if value is None:
        raise HistoryConversionError("History timestamp is missing")
    if value.tzinfo is None:
        raise HistoryConversionError("History timestamp has no timezone")
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
        raise HistoryConversionError("Entry history is newer than the current entry")
    versions.append(entry)
    previous: list[BwPasswordHistory] = []
    seen = {entry.password or ""}
    for older, newer in reversed(list(pairwise(versions))):
        password = older.password or ""
        if "{REF:" in password.upper():
            raise HistoryConversionError(
                "Historical password references cannot be resolved at their original time; use --no-password-history --archive-history to retain their records"
            )
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
                raise HistoryConversionError(
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
