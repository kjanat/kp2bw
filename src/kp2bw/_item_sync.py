"""Shared content signatures for kp2bw-managed Bitwarden items."""

import hashlib

from .bw_types import BwField, BwItemCreate, BwItemLogin, BwItemResponse

KP2BW_ID_FIELD_NAME: str = "KP2BW_ID"
KP2BW_SYNC_FIELD_NAME: str = "KP2BW_SYNC"

_MANAGED_FIELD_NAMES: frozenset[str] = frozenset({
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
})


def fields_signature(fields: list[BwField] | None) -> list[tuple[str, str, int]]:
    """Return an order-independent signature excluding kp2bw's own stamps."""
    return sorted(
        (
            (field.get("name") or "", field.get("value") or "", field.get("type") or 0)
            for field in (fields or [])
            if (field.get("name") or "") not in _MANAGED_FIELD_NAMES
        ),
        key=lambda value: (value[0], value[2], value[1]),
    )


def login_signature(login: BwItemLogin | None) -> tuple[str, str, str, list[str]]:
    """Return the signature of login fields kp2bw owns."""
    if login is None:
        return ("", "", "", [])
    return (
        login.get("username") or "",
        login.get("password") or "",
        login.get("totp") or "",
        [uri.get("uri", "") for uri in (login.get("uris") or [])],
    )


def content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return a digest over exactly the item content kp2bw manages."""
    blob = repr((
        item.get("name") or "",
        item.get("notes") or "",
        fields_signature(item.get("fields")),
        login_signature(item.get("login")),
    ))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def stamp_content(item: BwItemCreate | BwItemResponse) -> None:
    """Set the managed sync field to the item's current content signature."""
    signature = content_signature(item)
    for field in reversed(item["fields"]):
        if field["name"] == KP2BW_SYNC_FIELD_NAME:
            field["value"] = signature
            field["type"] = 0
            return
    item["fields"].append(BwField(name=KP2BW_SYNC_FIELD_NAME, value=signature, type=0))
