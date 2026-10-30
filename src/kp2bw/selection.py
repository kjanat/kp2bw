"""Resolve explicit item selectors without title matching or destination writes."""

from dataclasses import dataclass
from uuid import UUID

from .bw_types import BwItemResponse
from .exceptions import ConversionError
from .item_sync import KP2BW_ID_FIELD_NAME


def source_uuid(value: str) -> str:
    """Canonical KeePass stamp spelling; reject malformed selectors."""
    try:
        return UUID(value).hex.upper()
    except ValueError as exc:
        raise ConversionError("Entry selection requires a valid UUID") from exc


@dataclass(frozen=True)
class ItemSelection:
    source_id: str
    destination_id: str | None


def resolve_selection(
    source_id: str | None,
    destination_id: str | None,
    visible: list[BwItemResponse],
    scoped_ids: set[str],
) -> ItemSelection:
    """Require a unique, in-scope association; a source may be new."""
    selected_source = source_uuid(source_id) if source_id is not None else None
    selected_destination = None
    if destination_id is not None:
        try:
            selected_destination = str(UUID(destination_id))
        except ValueError as exc:
            raise ConversionError("Item selection requires a valid UUID") from exc
        matches = [item for item in visible if item["id"] == selected_destination]
        if len(matches) != 1:
            raise ConversionError("Selected Bitwarden item is missing or ambiguous")
        stamps = [
            field.get("value")
            for field in matches[0].get("fields") or []
            if field.get("name") == KP2BW_ID_FIELD_NAME
        ]
        if len(stamps) != 1 or not stamps[0]:
            raise ConversionError("Selected item has no unique KeePass association")
        stamped_source = source_uuid(stamps[0])
        if selected_source is not None and selected_source != stamped_source:
            raise ConversionError("Entry and item selectors refer to different sources")
        selected_source = stamped_source
    if selected_source is None:
        raise ConversionError("An entry or item selector is required")

    associated: list[BwItemResponse] = []
    for item in visible:
        stamps = [
            field.get("value")
            for field in item.get("fields") or []
            if field.get("name") == KP2BW_ID_FIELD_NAME
        ]
        for stamp in stamps:
            if not stamp:
                continue
            try:
                matches_source = source_uuid(stamp) == selected_source
            except ConversionError:
                continue
            if matches_source:
                if len(stamps) != 1:
                    raise ConversionError(
                        "Selected source has ambiguous destination stamps"
                    )
                associated.append(item)
                break
    if len(associated) > 1:
        raise ConversionError("Selected source matches multiple Bitwarden items")
    if associated:
        item = associated[0]
        if item["id"] not in scoped_ids:
            raise ConversionError(
                "Selected item is outside the requested destination scope"
            )
        selected_destination = item["id"]
    return ItemSelection(selected_source, selected_destination)
