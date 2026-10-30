"""Compare CLI inventory snapshots without exposing their decrypted contents."""

import hashlib
import json
from typing import cast

from .exceptions import BitwardenClientError


def inventory_signature(value: object) -> str:
    if not isinstance(value, list):
        raise BitwardenClientError("CLI inventory is not a list")
    rows: dict[str, dict[str, object]] = {}
    for raw in cast(list[object], value):
        if not isinstance(raw, dict):
            raise BitwardenClientError("CLI inventory contains an invalid record")
        row = cast(dict[str, object], raw)
        identifier = row.get("id")
        # The official folder list includes a synthetic null-ID 'No Folder'.
        if "id" not in row or (
            identifier is not None and not isinstance(identifier, str)
        ):
            raise BitwardenClientError("CLI inventory contains an invalid identity")
        key = str(identifier)
        if key in rows:
            raise BitwardenClientError("CLI inventory contains duplicate identities")
        rows[key] = row
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
