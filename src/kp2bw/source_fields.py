"""Lossless names for source fields that collide with migration bookkeeping."""

from urllib.parse import quote, unquote

from .attachments import ATTACHMENT_FIELD_PREFIX

SOURCE_FIELD_PREFIX = "KeePass:"
RESERVED_FIELD_NAMES = frozenset({
    "KP2BW_ID",
    "KP2BW_SYNC",
    "KP2BW_META",
    "KP2BW_HISTORY",
})


def source_field_name(name: str, occurrence: int = 1) -> str:
    """Keep ordinary names; escape reserved names, our namespace and duplicates.

    Occurrences are one-based in source XML order. Escaping the prefix itself
    makes source-supplied lookalikes distinct from generated names.
    """
    if occurrence < 1:
        raise ValueError("Source field occurrence must be positive")
    if (
        name in RESERVED_FIELD_NAMES
        or name.startswith((ATTACHMENT_FIELD_PREFIX, SOURCE_FIELD_PREFIX))
        or occurrence > 1
    ):
        return f"{SOURCE_FIELD_PREFIX}{quote(name, safe='')}:{occurrence}"
    return name


def source_field_origin(name: str) -> tuple[str, int] | None:
    """Decode one generated name for maintenance tools without treating it as a stamp."""
    if not name.startswith(SOURCE_FIELD_PREFIX):
        return None
    encoded, separator, ordinal = name[len(SOURCE_FIELD_PREFIX) :].rpartition(":")
    if not separator or not ordinal.isascii() or not ordinal.isdecimal():
        return None
    occurrence = int(ordinal)
    if occurrence < 1:
        return None
    original = unquote(encoded)
    if source_field_name(original, occurrence) != name:
        return None
    return original, occurrence
