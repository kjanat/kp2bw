"""Bitwarden API types.

``_bw_api_types`` is auto-generated from ``specs/vault-management-api.json``
via ``scripts/generate-bw-types.sh`` — never edit it by hand.

This module re-exports those types and supplements with three categories of
things the upstream spec cannot express:

1. **Response shapes** — ``id``, ``object``, ``revisionDate`` are present on
   every item the server returns, but absent from the request-only
   ``item.template`` schema component.
2. **``uris`` list fix** — the spec types ``item.login.uris`` as a single
   ``Uris`` object; the real API uses ``list[Uris]``.  ``BwItemLogin``
   corrects this.
3. **``BwFido2Credential``** — KeePassXC passkey attributes added after the
   spec was written; not present in ``vault-management-api.json``.
"""

from typing import Literal, NotRequired, TypedDict

from ._bw_api_types import (
    Group,
    ItemCard,
    ItemIdentity,
    ItemSecureNote,
    LockunlockSuccess,
    Status,
    Uris,
)

__all__ = [
    "BwCollection",
    "BwFido2Credential",
    "BwField",
    "BwFolder",
    "BwItemCreate",
    "BwItemLogin",
    "BwItemResponse",
    "BwUri",
    "Group",
    "ItemCard",
    "ItemIdentity",
    "ItemSecureNote",
    "LockunlockSuccess",
    "Status",
    "Uris",
]


# ---------------------------------------------------------------------------
# Concrete URI and field types — stricter than the generated NotRequired versions
# ---------------------------------------------------------------------------


class BwUri(TypedDict):
    """Single URI entry on a login item.

    The spec types ``match`` as ``Literal[0–5]``; ``None`` is also valid and
    means "use Bitwarden's default match detection".
    """

    uri: str
    match: NotRequired[Literal[0, 1, 2, 3, 4, 5] | None]


class BwField(TypedDict):
    """Custom field on a vault item."""

    name: str
    value: str
    type: Literal[0, 1, 2, 3]  # text, hidden, boolean, linked


# ---------------------------------------------------------------------------
# Schema gap 1 — fido2Credentials (passkey support added after spec)
# ---------------------------------------------------------------------------


class BwFido2Credential(TypedDict):
    """FIDO2/passkey credential; absent from ``vault-management-api.json``."""

    credentialId: str
    keyType: str
    keyAlgorithm: str
    keyCurve: str
    keyValue: str
    rpId: str
    rpName: str
    userHandle: str
    userName: str
    userDisplayName: str
    counter: str
    discoverable: str
    creationDate: str | None


# ---------------------------------------------------------------------------
# Schema gap 2 — uris is a list, not a single object
# ---------------------------------------------------------------------------


class BwItemLogin(TypedDict):
    """Login sub-object.

    The spec types ``uris`` as a single ``Uris`` object; the actual API
    uses ``list[Uris]``.  This class corrects that.
    """

    uris: list[BwUri]
    username: str
    password: str
    totp: str | None
    passwordRevisionDate: str | None
    fido2Credentials: NotRequired[list[BwFido2Credential]]


# ---------------------------------------------------------------------------
# Item create payload and response — share a common base
# ---------------------------------------------------------------------------


class _BwItemCommon(TypedDict):
    """Fields shared across both the create payload and every API response.

    ``notes`` and ``collectionIds`` are typed nullable because ``bw serve``
    returns ``null`` for both on personal-vault items (secure notes without
    notes text, items not in a collection), despite the OpenAPI schema marking
    them ``NotRequired`` rather than nullable.

    ``login`` is intentionally absent from this base: ``BwItemCreate`` declares
    it required (kp2bw only migrates login-type entries) and ``BwItemResponse``
    declares it ``NotRequired`` (the API omits it on cards, secure notes, and
    identities).  Keeping both declarations in their respective subclasses avoids
    a TypedDict field override, which type checkers cannot represent.
    """

    organizationId: str | None
    collectionIds: list[str] | None
    folderId: str | None
    type: int
    name: str
    notes: str | None
    favorite: bool
    fields: list[BwField]
    secureNote: ItemSecureNote | None
    card: ItemCard | None
    identity: ItemIdentity | None


class BwItemCreate(_BwItemCommon):
    """Payload for ``POST /object/item`` and ``PUT /object/item/{id}``.

    kp2bw exclusively migrates login-type entries, so ``login`` is required.
    """

    login: BwItemLogin


class BwItemResponse(_BwItemCommon):
    """Item returned by ``GET /list/object/items`` and ``POST /object/item``.

    Server appends ``id``, ``object``, ``revisionDate`` to the template shape.
    ``deletedDate`` is absent on live items.  ``login`` is ``NotRequired``
    because non-login items (cards, secure notes, identities) lack it.
    """

    id: str
    object: str
    revisionDate: str
    deletedDate: NotRequired[str | None]
    login: NotRequired[BwItemLogin]  # absent on non-login vault items


# ---------------------------------------------------------------------------
# Schema gap 3 — folder/collection responses include id and object
# ---------------------------------------------------------------------------


class BwFolder(TypedDict):
    """Folder entry from ``GET /list/object/folders``."""

    id: str
    name: str
    object: NotRequired[str]


class BwCollection(TypedDict):
    """Collection entry from ``GET /list/object/org-collections``."""

    id: str
    organizationId: str
    name: str
    externalId: str | None
    object: NotRequired[str]
    groups: NotRequired[list[Group]]
