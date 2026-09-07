"""Regression checks for KeePassXC-to-Bitwarden passkey conversion."""

import copy
from types import SimpleNamespace
from typing import Any, cast

from pykeepass import Entry

from kp2bw._item_sync import (
    BW_B64_CREDENTIAL_ID_PREFIX,
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
    pre_fido2_content_signature,
    stamp_content,
    sync_stamp_generation,
)
from kp2bw.bw_serve import BitwardenServeClient, item_kp2bw_sync
from kp2bw.bw_types import BwFido2Credential, BwItemCreate, BwItemResponse
from kp2bw.convert import Converter

SOURCE_ID = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
MARKED_ID = f"{BW_B64_CREDENTIAL_ID_PREFIX}{SOURCE_ID}"


def _converter() -> Converter:
    """Build a converter that never connects to a live vault."""
    return Converter(
        keepass_file_path="dummy.kdbx",
        keepass_password="pw",
        keepass_keyfile_path=None,
        bitwarden_password="pw",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
    )


def _credential_id(converted_id: str) -> str:
    """Convert a representative passkey and return its Bitwarden ID."""
    entry = cast(
        Entry,
        SimpleNamespace(title="Passkey", username="alice", ctime=None),
    )
    credentials = _converter()._build_fido2_credentials(
        entry,
        {
            "KPEX_PASSKEY_CREDENTIAL_ID": converted_id,
            "KPEX_PASSKEY_PRIVATE_KEY_PEM": (
                "-----BEGIN PRIVATE KEY-----\nAAE=\n-----END PRIVATE KEY-----"
            ),
            "KPEX_PASSKEY_RELYING_PARTY": "example.com",
            "KPEX_PASSKEY_USER_HANDLE": "dXNlci1oYW5kbGU",
            "KPEX_PASSKEY_USERNAME": "alice",
        },
    )
    if credentials is None:
        raise AssertionError("passkey conversion unexpectedly returned no credential")
    return credentials[0]["credentialId"]


def _credential(credential_id: str, *, rp_id: str = "example.com") -> BwFido2Credential:
    return BwFido2Credential(
        credentialId=credential_id,
        keyType="public-key",
        keyAlgorithm="ECDSA",
        keyCurve="P-256",
        keyValue="AAE",
        rpId=rp_id,
        rpName=rp_id,
        userHandle="dXNlci1oYW5kbGU",
        userName="alice",
        userDisplayName="alice",
        counter="0",
        discoverable="true",
        creationDate=None,
    )


def _desired(credentials: list[BwFido2Credential] | None) -> BwItemCreate:
    """A freshly converted item, stamped the way the migration emits it."""
    item: dict[str, Any] = {
        "organizationId": None,
        "collectionIds": [],
        "folderId": None,
        "type": 1,
        "name": "Passkey",
        "notes": "",
        "favorite": False,
        "fields": [{"name": KP2BW_ID_FIELD_NAME, "value": "UUID", "type": 0}],
        "login": {
            "uris": [],
            "username": "alice",
            "password": "",
            "totp": None,
            "passwordRevisionDate": None,
        },
        "secureNote": None,
        "card": None,
        "identity": None,
    }
    if credentials is not None:
        item["login"]["fido2Credentials"] = credentials
    desired = cast(BwItemCreate, item)
    stamp_content(desired)
    return desired


def _existing_from_3_8_1(credentials: list[BwFido2Credential] | None) -> BwItemResponse:
    """A vault item as kp2bw 3.8.1 wrote it, stamped without passkey coverage."""
    item: dict[str, Any] = dict(_desired(credentials))
    item.update({
        "object": "item",
        "id": "item-1",
        "revisionDate": "2026-01-01T00:00:00Z",
    })
    existing = cast(BwItemResponse, item)
    existing["fields"] = [
        {"name": KP2BW_ID_FIELD_NAME, "value": "UUID", "type": 0},
        {
            "name": KP2BW_SYNC_FIELD_NAME,
            "value": pre_fido2_content_signature(existing),
            "type": 0,
        },
    ]
    return existing


class _FakeBw:
    def __init__(self) -> None:
        self.updates: list[BwItemResponse] = []

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        self.updates.append(item)

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        pass


def _reconcile(
    existing: BwItemResponse, desired: BwItemCreate
) -> tuple[str, list[BwItemResponse]]:
    fake = _FakeBw()
    outcome, _, _ = _converter()._reconcile_existing_item(
        cast(BitwardenServeClient, fake),
        existing,
        None,
        desired,
        [],
        fixed_coll_id=None,
        kp_uuid="UUID",
    )
    return outcome, fake.updates


def assert_base64url_credential_id_uses_bitwarden_marker() -> None:
    """A KeePassXC byte-string ID must not be parsed as a Bitwarden UUID."""
    if _credential_id(SOURCE_ID) != MARKED_ID:
        raise AssertionError(
            "base64url credential ID is missing Bitwarden's b64 marker"
        )


def assert_existing_bitwarden_marker_is_preserved() -> None:
    """Defensively avoid adding the marker twice."""
    if _credential_id(MARKED_ID) != MARKED_ID:
        raise AssertionError("existing Bitwarden b64 marker was duplicated")


def assert_rerun_repairs_unmarked_credential_id() -> None:
    """An item migrated before the marker existed is rewritten on the next run."""
    existing = _existing_from_3_8_1([_credential(SOURCE_ID)])
    outcome, updates = _reconcile(existing, _desired([_credential(MARKED_ID)]))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(f"pre-marker passkey item was not repaired: {outcome}")
    payload = updates[0]
    login = payload.get("login")
    written = (login.get("fido2Credentials") or []) if login is not None else []
    if [credential["credentialId"] for credential in written] != [MARKED_ID]:
        raise AssertionError("repair PUT did not carry the marked credential ID")
    stamp = item_kp2bw_sync(payload)
    if stamp is None or sync_stamp_generation(payload, stamp) != "current":
        raise AssertionError("repair PUT did not restamp with passkey coverage")


def assert_repaired_passkey_item_is_idempotent() -> None:
    """The repaired item, read back unchanged, is skipped on the following run."""
    existing = _existing_from_3_8_1([_credential(SOURCE_ID)])
    _, updates = _reconcile(existing, _desired([_credential(MARKED_ID)]))
    repaired = copy.deepcopy(updates[0])
    outcome, updates = _reconcile(repaired, _desired([_credential(MARKED_ID)]))
    if outcome != "skipped" or updates:
        raise AssertionError(f"repaired passkey item was written again: {outcome}")


def assert_bitwarden_passkey_edit_under_old_stamp_is_protected() -> None:
    """A passkey that changed in Bitwarden under a 3.8.1 stamp is preserved."""
    existing = _existing_from_3_8_1([_credential(SOURCE_ID, rp_id="edited.example")])
    outcome, updates = _reconcile(existing, _desired([_credential(MARKED_ID)]))
    if outcome != "protected" or updates:
        raise AssertionError(f"edited passkey was overwritten: {outcome}")


def assert_keepass_added_passkey_under_old_stamp_syncs() -> None:
    """A passkey added in KeePassXC reaches an item that had none."""
    existing = _existing_from_3_8_1(None)
    outcome, updates = _reconcile(existing, _desired([_credential(MARKED_ID)]))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(f"new KeePassXC passkey was not synced: {outcome}")


def assert_strict_signature_ignores_marker() -> None:
    """Legacy REF output written before the marker still matches exactly."""
    unmarked = _desired([_credential(SOURCE_ID)])["login"]
    marked = _desired([_credential(MARKED_ID)])["login"]
    if Converter._strict_login_signature(unmarked) != Converter._strict_login_signature(
        marked
    ):
        raise AssertionError("credential ID marker changed the strict REF signature")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_base64url_credential_id_uses_bitwarden_marker()
    assert_existing_bitwarden_marker_is_preserved()
    assert_rerun_repairs_unmarked_credential_id()
    assert_repaired_passkey_item_is_idempotent()
    assert_bitwarden_passkey_edit_under_old_stamp_is_protected()
    assert_keepass_added_passkey_under_old_stamp_syncs()
    assert_strict_signature_ignores_marker()


if __name__ == "__main__":
    main()
