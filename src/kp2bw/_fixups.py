"""Registered, field-local upgrades for existing Bitwarden items."""

import copy
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
    Token,
)

from ._item_sync import (
    KP2BW_SYNC_FIELD_NAME,
    legacy_extensions_are_ambiguous,
    stamp_content,
    sync_stamp_generation,
)
from .bw_serve import BitwardenServeClient, item_revision
from .bw_types import BwItemResponse
from .exceptions import BitwardenClientError, FixupDataError
from .uri_mapping import UriMatchValue, is_url_attribute_key, remap_item_fields_to_uris

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FixupOptions:
    plain_match: UriMatchValue = None
    interpret_syntax: bool = True


@dataclass(frozen=True)
class Fixup:
    name: str
    transform: Callable[[BwItemResponse, FixupOptions], bool]


@dataclass
class FixupResult:
    scanned: int = 0
    migrated: int = 0
    skipped: int = 0
    failed: int = 0


def _metadata(item: BwItemResponse, _options: FixupOptions) -> bool:
    fields = [
        field for field in item.get("fields") or [] if field.get("name") == "KP2BW_META"
    ]
    if not fields:
        return False
    if len(fields) != 1:
        raise FixupDataError("Duplicate metadata fields")
    field = fields[0]
    value = field.get("value")
    if field.get("type") != 0 or field.get("linkedId") is not None or not value:
        raise FixupDataError("Unrecognized metadata field representation")
    try:
        tokens = cast(Iterable[Token], yaml.scan(value))  # pyright: ignore[reportUnknownMemberType]
        depth = 0
        for token in tokens:
            if isinstance(token, (AliasToken, AnchorToken)):
                raise FixupDataError(
                    "Metadata aliases or anchors are not a known legacy representation"
                )
            if isinstance(
                token,
                (
                    BlockMappingStartToken,
                    BlockSequenceStartToken,
                    FlowMappingStartToken,
                    FlowSequenceStartToken,
                ),
            ):
                depth += 1
                if depth > 2:
                    raise FixupDataError(
                        "Nested metadata is not a known legacy representation"
                    )
            elif isinstance(
                token, (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken)
            ):
                depth -= 1
        document = cast(Node | None, yaml.compose(value, Loader=yaml.SafeLoader))  # pyright: ignore[reportUnknownMemberType]
    except yaml.YAMLError as exc:
        raise FixupDataError("Malformed metadata") from exc
    if (
        not isinstance(document, MappingNode)
        or document.tag != "tag:yaml.org,2002:map"
        or not document.value
    ):
        raise FixupDataError("Metadata must be a nonempty mapping")
    metadata: dict[str, str | list[str]] = {}
    for key, node in document.value:
        if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
            raise FixupDataError("Unrecognized metadata key")
        if key.value not in {"expires", "tags"} or key.value in metadata:
            raise FixupDataError("Unknown or duplicate metadata key")
        if key.value == "tags":
            if (
                not isinstance(node, SequenceNode)
                or node.tag != "tag:yaml.org,2002:seq"
            ):
                raise FixupDataError("Metadata tags must be a list of strings")
            tags: list[str] = []
            for tag in node.value:
                if (
                    not isinstance(tag, ScalarNode)
                    or tag.tag != "tag:yaml.org,2002:str"
                ):
                    raise FixupDataError("Metadata tags must be strings")
                tags.append(tag.value)
            metadata["tags"] = tags
        else:
            if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:str":
                raise FixupDataError("Metadata expiry must be an ISO timestamp string")
            try:
                datetime.fromisoformat(node.value)
            except ValueError as exc:
                raise FixupDataError("Invalid metadata expiry timestamp") from exc
            if "T" not in node.value:
                raise FixupDataError("Metadata expiry must include a time")
            metadata["expires"] = node.value
    try:
        json.loads(value)
    except json.JSONDecodeError:
        field["value"] = json.dumps(metadata, ensure_ascii=True, sort_keys=True)
        return True
    return False


def _uris(item: BwItemResponse, options: FixupOptions) -> bool:
    fields = item.get("fields") or []
    legacy = [
        field for field in fields if is_url_attribute_key(field.get("name") or "")
    ]
    if not legacy:
        return False
    login = item.get("login")
    if item.get("type") != 1 or login is None:
        raise FixupDataError("Legacy URL fields are not on a login item")
    if any(
        field.get("type") != 0
        or field.get("linkedId") is not None
        or not (field.get("value") or "").strip()
        for field in legacy
    ):
        raise FixupDataError("URL fields must be nonempty ordinary text fields")
    for field in legacy:
        _, derived, _ = remap_item_fields_to_uris(
            [field],
            [],
            plain_match=options.plain_match,
            interpret_syntax=options.interpret_syntax,
        )
        if not derived:
            raise FixupDataError("URL field has no lossless URI representation")
    fields, uris, changed = remap_item_fields_to_uris(
        fields,
        login.get("uris") or [],
        plain_match=options.plain_match,
        interpret_syntax=options.interpret_syntax,
    )
    item["fields"] = fields
    login["uris"] = uris
    return changed


REGISTRY = (Fixup("uris", _uris), Fixup("metadata", _metadata))


def _in_scope(
    item: BwItemResponse, org_id: str | None, collection_id: str | None
) -> bool:
    return item.get("organizationId") == org_id and (
        collection_id is None or collection_id in (item.get("collectionIds") or [])
    )


def run_fixups(
    client: BitwardenServeClient,
    *,
    org_id: str | None = None,
    collection_id: str | None = None,
    options: FixupOptions | None = None,
) -> FixupResult:
    """Upgrade known representations, retaining edits and rejecting ambiguous data."""
    options = options or FixupOptions()
    result = FixupResult()
    for listed in client.list_items(
        organization_id=org_id, collection_id=collection_id
    ):
        if not _in_scope(listed, org_id, collection_id):
            continue
        result.scanned += 1
        if not any(
            field.get("name") == "KP2BW_META"
            or is_url_attribute_key(field.get("name") or "")
            for field in listed.get("fields") or []
        ):
            result.skipped += 1
            continue
        item_id = listed["id"]
        try:
            fresh = client.get_item(item_id)
            if not _in_scope(fresh, org_id, collection_id):
                result.skipped += 1
                logger.warning("Skipping item %s: scope changed", item_id)
                continue
            stamps = [
                field.get("value")
                for field in fresh.get("fields") or []
                if field.get("name") == KP2BW_SYNC_FIELD_NAME
            ]
            if stamps:
                if len(stamps) != 1 or not stamps[0]:
                    raise FixupDataError("Missing or ambiguous sync stamp value")
                generation = sync_stamp_generation(fresh, stamps[0])
                if generation is None or legacy_extensions_are_ambiguous(
                    fresh, generation
                ):
                    logger.warning(
                        "Skipping item %s: sync stamp cannot verify its current content",
                        item_id,
                    )
                    result.skipped += 1
                    continue
            item = copy.deepcopy(fresh)
            changed = False
            for fixup in REGISTRY:
                changed = fixup.transform(item, options) or changed
            if not changed:
                result.skipped += 1
                continue
            stamp_content(item)
            latest = client.get_item(item_id)
            if client.item_update_body(latest) != client.item_update_body(fresh):
                logger.warning("Skipping item %s: changed during fixup", item_id)
                result.skipped += 1
                continue
            revision = item_revision(latest)
            if revision is None:
                raise FixupDataError("No revision available for a conditional update")
            client.update_item_if_revision(item_id, item, expected_revision=revision)
            result.migrated += 1
        except FixupDataError as exc:
            logger.warning("Fixup left item %s unchanged: %s", item_id, exc)
            result.failed += 1
        except BitwardenClientError as exc:
            logger.warning(
                "Fixup failed for item %s (%s); no further writes attempted for this item",
                item_id,
                type(exc).__name__,
            )
            result.failed += 1
    return result
