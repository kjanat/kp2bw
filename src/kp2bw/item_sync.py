"""Shared content signatures for kp2bw-managed Bitwarden items."""

import hashlib
import re
from typing import Literal

from .bw_types import (
    BwFido2Credential,
    BwField,
    BwItemCreate,
    BwItemLogin,
    BwItemResponse,
)
from .history import has_managed_history, history_signature

KP2BW_ID_FIELD_NAME: str = "KP2BW_ID"
KP2BW_SYNC_FIELD_NAME: str = "KP2BW_SYNC"
BW_B64_CREDENTIAL_ID_PREFIX: str = "b64."

MANAGED_FIELD_NAMES: frozenset[str] = frozenset({
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
})

UUID_CREDENTIAL_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

type SyncStampGeneration = Literal["current", "pre_history", "pre_fido2", "legacy"]
type Fido2CredentialSignature = tuple[str, str, str, str, str, str, str]
type Fido2Signature = list[Fido2CredentialSignature]


def mark_credential_id(credential_id: str) -> str:
    """Prefix a base64url credential ID with Bitwarden's ``b64.`` marker."""
    if credential_id.startswith(
        BW_B64_CREDENTIAL_ID_PREFIX
    ) or UUID_CREDENTIAL_ID.match(credential_id):
        return credential_id
    return f"{BW_B64_CREDENTIAL_ID_PREFIX}{credential_id}"


def legacy_fields_signature(
    fields: list[BwField] | None,
) -> list[tuple[str, str, int]]:
    """Return the signature emitted before linked fields were covered."""
    return sorted(
        (
            (field.get("name") or "", field.get("value") or "", field.get("type") or 0)
            for field in (fields or [])
            if (field.get("name") or "") not in MANAGED_FIELD_NAMES
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
            if (field.get("name") or "") not in MANAGED_FIELD_NAMES
        ),
        key=lambda value: (
            value[0],
            value[2],
            value[1],
            -1 if value[3] is None else value[3],
        ),
    )


def legacy_login_signature(
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


def fido2_credential_signature(
    credential: BwFido2Credential, *, mark_id: bool
) -> Fido2CredentialSignature:
    """Return the signature of one passkey, optionally with its ID marked."""
    credential_id = credential.get("credentialId") or ""
    return (
        mark_credential_id(credential_id) if mark_id else credential_id,
        credential.get("keyValue") or "",
        credential.get("rpId") or "",
        credential.get("rpName") or "",
        credential.get("userHandle") or "",
        credential.get("userName") or "",
        credential.get("userDisplayName") or "",
    )


def fido2_credentials(
    item: BwItemResponse | BwItemCreate,
) -> list[BwFido2Credential]:
    """Return the item's passkeys, or an empty list without a login."""
    login = item.get("login")
    if login is None:
        return []
    return login.get("fido2Credentials") or []


def fido2_signature(login: BwItemLogin | None) -> Fido2Signature:
    """Return an order-independent signature of the passkey content kp2bw owns."""
    if login is None:
        return []
    return sorted(
        fido2_credential_signature(credential, mark_id=False)
        for credential in (login.get("fido2Credentials") or [])
    )


def content_parts(
    item: BwItemResponse | BwItemCreate,
) -> tuple[
    str,
    str,
    list[tuple[str, str, int, int | None]],
    tuple[str, str, str, list[tuple[str, int | None]]],
]:
    """Return the signature inputs shared by the current and 3.8.1 algorithms."""
    return (
        item.get("name") or "",
        item.get("notes") or "",
        fields_signature(item.get("fields")),
        login_signature(item.get("login")),
    )


def content_signature(
    item: BwItemResponse | BwItemCreate, *, include_history: bool = True
) -> str:
    """Return a digest over exactly the item content kp2bw manages."""
    if item.get("type", 1) != 1:
        native = (
            item.get("card")
            if item.get("type") == 3
            else item.get("identity")
            if item.get("type") == 4
            else item.get("sshKey")
            if item.get("type") == 5
            else item.get("secureNote")
        ) or {}
        native_content = (
            item.get("type"),
            item.get("name") or "",
            item.get("notes") or "",
            fields_signature(item.get("fields")),
            sorted(
                (key, value) for key, value in native.items() if value not in (None, "")
            ),
        )
        blob = repr(
            (*native_content, history_signature(item))
            if include_history and has_managed_history(item)
            else native_content
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
    parts = content_parts(item)
    fido2 = fido2_signature(item.get("login"))
    content = (*parts, fido2) if fido2 else parts
    blob = repr(
        (*content, history_signature(item))
        if include_history and has_managed_history(item)
        else content
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def pre_fido2_content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return the 3.8.1 signature, which did not cover passkeys."""
    blob = repr(content_parts(item))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def pre_history_content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return the signature before native history became part of item content."""
    return content_signature(item, include_history=False)


def is_legacy_history_source(item: BwItemResponse | BwItemCreate) -> bool:
    """An authenticated pre-history stamp treats the marker name as source data."""
    if not has_managed_history(item):
        return False
    stamps = [
        field.get("value")
        for field in item.get("fields") or []
        if field.get("name") == KP2BW_SYNC_FIELD_NAME
    ]
    return stamps == [pre_history_content_signature(item)]


def legacy_content_signature(item: BwItemResponse | BwItemCreate) -> str:
    """Return the pre-3.8.1 signature for compatibility with existing stamps."""
    blob = repr((
        item.get("name") or "",
        item.get("notes") or "",
        legacy_fields_signature(item.get("fields")),
        legacy_login_signature(item.get("login")),
    ))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def sync_stamp_generation(
    item: BwItemResponse, stamp: str
) -> SyncStampGeneration | None:
    """Return which signature algorithm produced *stamp* for *item*, if any."""
    if stamp == content_signature(item):
        return "current"
    if has_managed_history(item):
        return "pre_history" if is_legacy_history_source(item) else None
    if item.get("type", 1) != 1:
        return None
    if stamp == pre_fido2_content_signature(item):
        return "pre_fido2"
    if stamp == legacy_content_signature(item):
        return "legacy"
    return None


def sync_stamp_matches(item: BwItemResponse, stamp: str) -> bool:
    """Accept current stamps and older stamps over their original coverage."""
    return sync_stamp_generation(item, stamp) is not None


def legacy_extensions_are_ambiguous(
    item: BwItemResponse, generation: SyncStampGeneration
) -> bool:
    """Return whether an older stamp omitted live values that cannot be verified."""
    if generation == "current":
        return False
    if fido2_credentials(item):
        return True
    if generation != "legacy":
        return False
    login = item.get("login")
    if login is not None and login.get("uris"):
        return True
    return any(
        field.get("type") == 3 or field.get("linkedId") is not None
        for field in (item.get("fields") or [])
    )


def fido2_differs(
    existing: BwItemResponse, desired: BwItemCreate | BwItemResponse
) -> bool:
    """Compare passkeys, accepting an existing ID with or without its marker."""
    existing_fido2 = fido2_credentials(existing)
    desired_fido2 = fido2_signature(desired.get("login"))
    if len(existing_fido2) != len(desired_fido2):
        return True
    desired_set = set(desired_fido2)
    return any(
        fido2_credential_signature(credential, mark_id=False) not in desired_set
        and fido2_credential_signature(credential, mark_id=True) not in desired_set
        for credential in existing_fido2
    )


def legacy_extensions_differ(
    existing: BwItemResponse,
    desired: BwItemCreate | BwItemResponse,
    generation: SyncStampGeneration | None,
) -> bool:
    """Compare values an older stamp omitted that can be aligned under it."""
    if generation is None or generation == "current":
        return False
    if fido2_differs(existing, desired):
        return True
    if generation != "legacy":
        return False

    def linked_ids(
        item: BwItemResponse | BwItemCreate,
    ) -> dict[tuple[str, str, int], list[int | None]]:
        result: dict[tuple[str, str, int], list[int | None]] = {}
        for field in item.get("fields") or []:
            name = field.get("name") or ""
            if name in MANAGED_FIELD_NAMES:
                continue
            if field.get("type") != 3 and field.get("linkedId") is None:
                continue
            key = (name, field.get("value") or "", field.get("type") or 0)
            result.setdefault(key, []).append(field.get("linkedId"))
        return result

    def uri_matches(
        item: BwItemResponse | BwItemCreate,
    ) -> dict[str, list[int | None]]:
        result: dict[str, list[int | None]] = {}
        login = item.get("login")
        for uri in (login.get("uris") or []) if login is not None else []:
            result.setdefault(uri.get("uri", ""), []).append(uri.get("match"))
        return result

    existing_fields = linked_ids(existing)
    desired_fields = linked_ids(desired)
    if existing_fields.keys() != desired_fields.keys():
        return True
    if any(
        existing_fields[key] != desired_fields[key]
        for key in existing_fields.keys() & desired_fields.keys()
    ):
        return True

    existing_uris = uri_matches(existing)
    desired_uris = uri_matches(desired)
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
