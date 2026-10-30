"""Metadata-only descriptions of the actual prepared migration payloads."""

from dataclasses import asdict, dataclass, field
from typing import Literal, cast

from pykeepass import Entry, Group

from ._attachment_capability import AttachmentCapability
from ._attachments import SourceFile
from ._history import HISTORY_FIELD_NAME
from .bw_types import BwItemCreate


def source_inventory(entry: Entry) -> dict[str, int]:
    """Count source categories before REF resolution changes entry values."""
    xml = entry._element
    return {
        "history_records": len(xml.findall("History/Entry")),
        "original_attachments": len(xml.findall("Binary")),
        "custom_icons": int(bool(xml.findtext("CustomIconUUID"))),
        "builtin_icons": int(xml.findtext("IconID") not in (None, "0")),
        "autotype_associations": len(xml.findall("AutoType/Association")),
        "autotype_sequences": int(bool(xml.findtext("AutoType/DefaultSequence"))),
        "custom_fields": sum(
            node.findtext("Key")
            not in {"Title", "UserName", "Password", "URL", "Notes"}
            for node in xml.findall("String")
        ),
        "passkey_fields": sum(
            (node.findtext("Key") or "").startswith("KPEX_PASSKEY_")
            for node in xml.findall("String")
        ),
        "tags": len(entry.tags),
        "expiry": int(bool(entry.expires)),
    }


@dataclass(frozen=True)
class PreviewGroup:
    source_id: str
    omitted: dict[str, int]


def group_inventory(groups: list[Group]) -> list[PreviewGroup]:
    """Account for group data which folder/collection names cannot preserve."""
    result: list[PreviewGroup] = []
    for group in groups:
        xml = group._element
        counts = {
            "notes": int(bool(xml.findtext("Notes"))),
            "custom_icons": int(bool(xml.findtext("CustomIconUUID"))),
            "builtin_icons": int(xml.findtext("IconID") not in (None, "0", "48")),
            "autotype_sequences": int(bool(xml.findtext("DefaultAutoTypeSequence"))),
            "custom_data": len(xml.findall("CustomData/Item")),
            "timestamps": len(xml.findall("Times/*")),
        }
        result.append(
            PreviewGroup(group.uuid.hex.upper(), {k: v for k, v in counts.items() if v})
        )
    return result


@dataclass(frozen=True)
class PreviewAttachment:
    source_id: str
    kind: str
    filename: str
    bytes: int
    filename_final: bool = True


def describe_attachments(files: list[SourceFile]) -> list[PreviewAttachment]:
    return [
        PreviewAttachment(f.source_id, f.kind, f.filename, len(f.data)) for f in files
    ]


@dataclass
class PreviewEntry:
    source_id: str
    outcome: Literal[
        "planned",
        "merged",
        "excluded",
        "unresolved",
        "blocked",
        "create",
        "update",
        "unchanged",
        "protected",
    ]
    target_id: str | None = None
    uploads: int = 0
    upload_bytes: int = 0
    cleanup_attachments: int = 0
    attachment_capability: AttachmentCapability | None = None
    destination_source_id: str | None = None
    item_type: int | None = None
    native_fields: list[str] = field(default_factory=list)
    custom_fields: int = 0
    hidden_fields: int = 0
    passkeys: int = 0
    password_history: int = 0
    attachments: list[PreviewAttachment] = field(default_factory=list)
    source: dict[str, int] = field(default_factory=dict)
    omissions: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    metadata: list[str] = field(default_factory=list)


@dataclass
class MigrationPreview:
    entries: list[PreviewEntry]
    groups: list[PreviewGroup] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    target_inspected: bool = False
    schema_version: int = 1
    attachment_capability: AttachmentCapability | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = asdict(self)
        result["summary"] = {
            "source_entries": len(self.entries),
            "destination_items": sum(
                e.outcome in {"planned", "create", "update", "unchanged", "protected"}
                for e in self.entries
            ),
            "attachments": sum(len(e.attachments) for e in self.entries),
            "attachment_bytes": sum(
                a.bytes for e in self.entries for a in e.attachments
            ),
            "planned_upload_bytes": sum(e.upload_bytes for e in self.entries),
            "blocked_entries": sum(bool(e.blockers) for e in self.entries),
            "omitted_categories": sum(len(e.omissions) for e in self.entries),
            "group_omitted_categories": sum(len(g.omitted) for g in self.groups),
        }
        return result


def describe_payload(
    preview: PreviewEntry, item: BwItemCreate, files: list[SourceFile]
) -> None:
    """Project names, counts and sizes; never serialize a destination payload."""
    preview.item_type = item["type"]
    for key in ("name", "notes"):
        if item.get(key):
            preview.native_fields.append(key)
    section = {1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey"}.get(
        item["type"]
    )
    if section:
        values = item.get(section)
        if isinstance(values, dict):
            preview.native_fields.extend(
                f"{section}.{key}"
                for key, value in cast(dict[str, object], values).items()
                if value not in (None, "", [], {})
            )
    for custom in item.get("fields") or []:
        name = custom.get("name") or ""
        if name in {
            "KP2BW_ID",
            "KP2BW_SYNC",
            "KP2BW_META",
            HISTORY_FIELD_NAME,
        } or name.startswith("KP2BW_FILE_"):
            if name == "KP2BW_META":
                preview.metadata.append("custom field KP2BW_META")
            continue
        preview.custom_fields += 1
        preview.hidden_fields += custom.get("type") == 1
    login = item.get("login") if item["type"] == 1 else None
    preview.passkeys = len(login.get("fido2Credentials") or []) if login else 0
    preview.password_history = len(item.get("passwordHistory") or [])
    preview.attachments = describe_attachments(files)
    if any(f.original_name == "KP2BW_META.txt" for f in files):
        preview.metadata.append("generated metadata attachment")


def format_preview(preview: MigrationPreview) -> str:
    """Render the same metadata exposed by the JSON report."""
    lines = [
        "Migration preview (destination inspected; no writes)"
        if preview.target_inspected
        else "Migration preview (source only; destination not inspected)"
    ]
    for entry in preview.entries:
        lines.append(
            f"{entry.source_id}: {entry.outcome}; type={entry.item_type}; "
            f"{entry.custom_fields} custom fields, {entry.passkeys} passkeys, "
            f"{entry.password_history} previous passwords"
        )
        for attachment in entry.attachments:
            lines.append(
                f"  {attachment.kind}: {attachment.filename!r} ({attachment.bytes} bytes)"
                + (
                    "; checkpoint suffix requires target inspection"
                    if not attachment.filename_final
                    else ""
                )
            )
        lines.extend(f"  Omitted: {reason}" for reason in entry.omissions)
        lines.extend(f"  Blocked: {reason}" for reason in entry.blockers)
        if entry.attachment_capability is not None:
            capability = entry.attachment_capability
            lines.append(
                f"  Attachment entitlement: {capability.allowed}; {capability.reason}"
            )
    lines.extend(f"Blocked: {reason}" for reason in preview.blockers)
    if preview.attachment_capability is not None:
        capability = preview.attachment_capability
        lines.append(
            f"Attachment entitlement: {capability.allowed}; {capability.reason}"
        )
    for group in preview.groups:
        if group.omitted:
            lines.append(f"Group {group.source_id}: omitted {', '.join(group.omitted)}")
    total = sum(a.bytes for e in preview.entries for a in e.attachments)
    lines.append(f"{len(preview.entries)} source entries; {total} attachment bytes")
    return "\n".join(lines)
