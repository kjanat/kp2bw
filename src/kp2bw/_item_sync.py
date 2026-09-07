"""Shared content signatures for kp2bw-managed Bitwarden items."""

import hashlib
from typing import Literal

from .bw_types import (
    BwFido2Credential,
    BwField,
    BwItemCreate,
    BwItemLogin,
    BwItemResponse,
)

KP2BW_ID_FIELD_NAME: str = "KP2BW_ID"
KP2BW_SYNC_FIELD_NAME: str = "KP2BW_SYNC"
BW_B64_CREDENTIAL_ID_PREFIX: str = "b64."

_MANAGED_FIELD_NAMES: frozenset[str] = frozenset({
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
})

type SyncStampGeneration = Literal["current", "pre_fido2", "legacy"]
type Fido2Signature = list[tuple[str, str, str, str, str, str, str]]


def mark_credential_id(credential_id: str) -> str:
    """Prefix a base64url credential ID with Bitwarden's ``b64.`` marker."""
    if credential_id.startswith(BW_B64_CREDENTIAL_ID_PREFIX):
        return credential_id
    return f"{BW_B64_CREDENTIAL_ID_PREFIX}{credential_id}"


def _legacy_fields_signature(
    fields: list[BwField] | None,
) -> list[tuple[str, str, int]]:
    """Return the signature emitted before linked fields were covered."""
    return sorted(
        (
            (field.get("name") or "", field.get("value") or "", field.get("type") or 0)
            for field in (fields or [])
            if (field.get("name") or "") not in _MANAGED_FIELD_NAMES
        ),
        key=lambda value: (value[0], value[2], value[1]),
    )


def fields_signature(
    fields: list[BwField] | None,
) -> list[tuple[str, str, int, int | None]]:
    """Return an order-independent signature excluding kp2bw's own stamps."""
    return sorted(
        (
            (
                field.get("name") or "",
                field.get("value") or "",
                field.get("type") or 0,
                field.get("linkedId"),
            )
            for field in (fields or [])
            if (field.get("name") or "") not in _MANAGED_FIELD_NAMES
        ),
        key=lambda value: (
            value[0],
            value[2],
            value[1],
            -1 if value[3] is None else value[3],
        ),
    )


def _legacy_login_signature(
    login: BwItemLogin | None,
) -> tuple[str, str, str, list[str]]:
    """Return the signature emitted before URI match modes were covered."""
    if login is None:
        return ("", "", "", [])
    return (
        login.get("username") or "",
        login.get("password") or "",
        login.get("totp") or "",
        [uri.get("uri", "") for uri in (login.get("uris") or [])],
    )


def login_signature(
    login: BwItemLogin | None,
) -> tuple[str, str, str, list[tuple[str, int | None]]]:
    """Return the signature of login fields kp2bw owns."""
    if login is None:
        return ("", "", "", [])
    return (
        login.get("username") or "",
        login.get("password") or "",
        login.get("totp") or "",
        [(uri.get("uri", ""), uri.get("match")) for uri in (login.get("uris") or [])],
    )


def fido2_signature(
    login: BwItemLogin | None, *, mark_ids: bool = False
) -> Fido2Signature:
    """Return an order-independent signature of the passkey content kp2bw owns."""
    if login is None:
        return []

    def credential_id_of(credential: BwFido2Credential) -> str:
        value = credential.get("credentialId") or ""
        return mark_credential_id(value) if mark_ids else value

    return sorted(
        (
            credential_id_of(credential),
            credential.get("keyValue") or "",
            credential.get("rpId") or "",
            credential.get("rpName") or "",
            credential.get("userHandle") or "",
            credential.get("userName") or "",
            credential.get("userDisplayName") or "",
        )
        for credential in (login.get("fido2Credentials") or [])
    )


def _content_parts(
    item: BwItemResponse | BwItemCreate,
) -> tuple[
    str,
    str,
    list[tuple[str, str, int, int | None]],
    tuple[str, str, str, list[tuple[str, int | None]]],
]:
    return (
        item.get("name") or "",
        item.get("notes") or "",
        fields_signature(item.get("fields")),
        login_signature(item.get("login")),
    )


def content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return a digest over exactly the item content kp2bw manages."""
    parts = _content_parts(item)
    fido2 = fido2_signature(item.get("login"))
    blob = repr((*parts, fido2) if fido2 else parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def pre_fido2_content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return the 3.8.1 signature, which did not cover passkeys."""
    blob = repr(_content_parts(item))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def legacy_content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return the pre-3.8.1 signature for compatibility with existing stamps."""
    blob = repr((
        item.get("name") or "",
        item.get("notes") or "",
        _legacy_fields_signature(item.get("fields")),
        _legacy_login_signature(item.get("login")),
    ))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def sync_stamp_generation(
    item: BwItemResponse, stamp: str
) -> SyncStampGeneration | None:
    """Return which signature algorithm produced *stamp* for *item*, if any."""
    if stamp == content_signature(item):
        return "current"
    if stamp == pre_fido2_content_signature(item):
        return "pre_fido2"
    if stamp == legacy_content_signature(item):
        return "legacy"
    return None


def sync_stamp_matches(item: BwItemResponse, stamp: str) -> bool:
    """Accept current stamps and older stamps over their original coverage."""
    return sync_stamp_generation(item, stamp) is not None


def has_legacy_sync_stamp(item: BwItemResponse, stamp: str) -> bool:
    """Return whether *stamp* is valid only under the pre-3.8.1 algorithm."""
    return sync_stamp_generation(item, stamp) == "legacy"


def legacy_extensions_are_ambiguous(item: BwItemResponse) -> bool:
    """Return whether a legacy stamp omitted live values that cannot be verified."""
    login = item.get("login")
    if login is not None and login.get("uris"):
        return True
    return any(
        field.get("type") == 3 or field.get("linkedId") is not None
        for field in (item.get("fields") or [])
    )


def _fido2_differs(existing: BwItemResponse, desired: BwItemCreate) -> bool:
    existing_fido2 = fido2_signature(existing.get("login"), mark_ids=True)
    if not existing_fido2:
        return False
    return existing_fido2 != fido2_signature(desired.get("login"))


def legacy_extensions_differ(
    existing: BwItemResponse,
    desired: BwItemCreate,
    generation: SyncStampGeneration,
) -> bool:
    """Compare values an older stamp omitted that can be aligned under it."""
    if _fido2_differs(existing, desired):
        return True
    if generation != "legacy":
        return False

    def _linked_ids(
        item: BwItemResponse | BwItemCreate,
    ) -> dict[tuple[str, str, int], list[int | None]]:
        result: dict[tuple[str, str, int], list[int | None]] = {}
        for field in item.get("fields") or []:
            name = field.get("name") or ""
            if name in _MANAGED_FIELD_NAMES:
                continue
            if field.get("type") != 3 and field.get("linkedId") is None:
                continue
            key = (name, field.get("value") or "", field.get("type") or 0)
            result.setdefault(key, []).append(field.get("linkedId"))
        return result

    def _uri_matches(
        item: BwItemResponse | BwItemCreate,
    ) -> dict[str, list[int | None]]:
        result: dict[str, list[int | None]] = {}
        login = item.get("login")
        for uri in (login.get("uris") or []) if login is not None else []:
            result.setdefault(uri.get("uri", ""), []).append(uri.get("match"))
        return result

    existing_fields = _linked_ids(existing)
    desired_fields = _linked_ids(desired)
    if existing_fields.keys() != desired_fields.keys():
        return True
    if any(
        existing_fields[key] != desired_fields[key]
        for key in existing_fields.keys() & desired_fields.keys()
    ):
        return True

    existing_uris = _uri_matches(existing)
    desired_uris = _uri_matches(desired)
    if existing_uris.keys() != desired_uris.keys():
        return True
    return any(
        existing_uris[key] != desired_uris[key]
        for key in existing_uris.keys() & desired_uris.keys()
    )


def stamp_content(item: BwItemCreate | BwItemResponse) -> None:
    """Set the managed sync field to the item's current content signature."""
    signature = content_signature(item)
    for field in reversed(item["fields"]):
        if field["name"] == KP2BW_SYNC_FIELD_NAME:
            field["value"] = signature
            field["type"] = 0
            return
    item["fields"].append(BwField(name=KP2BW_SYNC_FIELD_NAME, value=signature, type=0))
