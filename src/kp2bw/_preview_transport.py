"""A simulated destination for the normal reconciliation path.

Only the explicitly supplied read callbacks can reach the live vault. Writes
replace in-memory item snapshots and are never forwarded to a real client.
"""

import copy
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ._checkpoint import AttachmentCheckpoint, CheckpointRecord, CheckpointScope
from .bw_serve import BitwardenServeClient
from .bw_types import BwItemResponse
from .exceptions import BitwardenClientError, ConversionError


class PreviewCheckpoint(AttachmentCheckpoint):
    """Read an atomic checkpoint snapshot and simulate subsequent saves in memory."""

    def __init__(self, path: Path, scope: CheckpointScope) -> None:
        super().__init__(path, scope)
        try:
            self._load()
        except OSError:
            raise ConversionError("Cannot read the attachment checkpoint") from None

    def save_many(self, updates: Sequence[CheckpointRecord]) -> None:
        records = {**self.records, **{record.key: record for record in updates}}
        self._check_destinations(records)
        self.records = records


class PreviewTransport(BitwardenServeClient):
    def __init__(
        self,
        read_item: Callable[[str], BwItemResponse],
        read_attachment: Callable[[str, str], bytes],
        validate_update: Callable[[str, BwItemResponse], None],
    ) -> None:
        self._read_item = read_item
        self._read_attachment = read_attachment
        self._validate_update = validate_update
        self._snapshots: dict[str, BwItemResponse] = {}
        self.updated_ids: set[str] = set()
        self.deleted_attachments: set[tuple[str, str]] = set()

    def sync(self, *, force: bool = False) -> None:
        # Simulated writes are already visible in the local snapshots.
        pass

    def delete_attachment(self, item_id: str, attachment_id: str) -> None:
        item = self.get_item(item_id)
        item["attachments"] = [
            attachment
            for attachment in item.get("attachments") or []
            if attachment["id"] != attachment_id
        ]
        self._snapshots[item_id] = item
        self.deleted_attachments.add((item_id, attachment_id))

    def get_item(self, item_id: str) -> BwItemResponse:
        if item_id not in self._snapshots:
            self._snapshots[item_id] = copy.deepcopy(self._read_item(item_id))
        return copy.deepcopy(self._snapshots[item_id])

    def get_attachment(self, item_id: str, attachment_id: str) -> bytes:
        return self._read_attachment(item_id, attachment_id)

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self._validate_update(item_id, item)
        self._snapshots[item_id] = copy.deepcopy(item)
        self.updated_ids.add(item_id)

    def update_item_if_revision(
        self, item_id: str, item: BwItemResponse, *, expected_revision: str
    ) -> None:
        if self.get_item(item_id).get("revisionDate") != expected_revision:
            raise BitwardenClientError("Preview observed a changed item revision")
        self.update_item(item_id, item)

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        # Reconciliation updates its local index after a simulated write.
        self._snapshots[item["id"]] = copy.deepcopy(item)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: dict[str, str] | None = None,
        idempotent: bool | None = None,
    ) -> dict[str, Any]:
        raise BitwardenClientError("Preview cannot perform a transport request")
