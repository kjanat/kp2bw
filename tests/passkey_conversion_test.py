"""Regression checks for KeePassXC-to-Bitwarden passkey conversion."""

import base64
import copy
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pykeepass import Entry, PyKeePass, create_database

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
            "KPEX_PASSKEY_PRIVATE_KEY_PEM": (supported_pem()),
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


def _desired(
    credentials: list[BwFido2Credential] | None, *, notes: str = ""
) -> BwItemCreate:
    """A freshly converted item, stamped the way the migration emits it."""
    item: dict[str, Any] = {
        "organizationId": None,
        "collectionIds": [],
        "folderId": None,
        "type": 1,
        "name": "Passkey",
        "notes": notes,
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


def assert_passkey_added_to_passkeyless_item_syncs() -> None:
    """A stamp over an item without passkeys reads as current, so KeePass wins."""
    existing = _existing_from_3_8_1(None)
    outcome, updates = _reconcile(existing, _desired([_credential(MARKED_ID)]))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(f"new KeePassXC passkey was not synced: {outcome}")


def assert_bitwarden_native_passkey_is_not_protected() -> None:
    """A UUID credential ID Bitwarden created itself must not look like an edit."""
    native_id = "3c9f2a1e-5b7d-4c8a-9e2f-1a2b3c4d5e6f"
    existing = _existing_from_3_8_1([_credential(native_id)])
    outcome, updates = _reconcile(existing, _desired(None, notes="renamed"))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(f"Bitwarden-native passkey blocked the update: {outcome}")
    login = updates[0].get("login")
    kept = (login.get("fido2Credentials") or []) if login is not None else []
    if [credential["credentialId"] for credential in kept] != [native_id]:
        raise AssertionError("Bitwarden-native credential ID was rewritten")


def assert_bitwarden_only_passkey_survives_and_settles() -> None:
    """A passkey KeePass never had is kept, restamped, and then left alone."""
    existing = _existing_from_3_8_1([_credential(MARKED_ID)])
    outcome, updates = _reconcile(existing, _desired(None))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(
            f"3.8.1 stamp on a passkey item was not repaired: {outcome}"
        )
    payload = updates[0]
    login = payload.get("login")
    kept = (login.get("fido2Credentials") or []) if login is not None else []
    if [credential["credentialId"] for credential in kept] != [MARKED_ID]:
        raise AssertionError("Bitwarden-only passkey was dropped by the update")
    stamp = item_kp2bw_sync(payload)
    if stamp is None or sync_stamp_generation(payload, stamp) != "current":
        raise AssertionError("update stamp does not cover the kept passkey")
    outcome, updates = _reconcile(copy.deepcopy(payload), _desired(None))
    if outcome != "skipped" or updates:
        raise AssertionError(f"kept passkey kept triggering writes: {outcome}")


def assert_kept_unmarked_passkey_is_repaired() -> None:
    """A 3.8.1-written passkey KeePass no longer yields still gets its marker."""
    existing = _existing_from_3_8_1([_credential(SOURCE_ID)])
    outcome, updates = _reconcile(existing, _desired(None))
    if outcome != "updated" or len(updates) != 1:
        raise AssertionError(f"kept unmarked passkey was not repaired: {outcome}")
    login = updates[0].get("login")
    kept = (login.get("fido2Credentials") or []) if login is not None else []
    if [credential["credentialId"] for credential in kept] != [MARKED_ID]:
        raise AssertionError("kept passkey was sealed without its marker")
    outcome, updates = _reconcile(copy.deepcopy(updates[0]), _desired(None))
    if outcome != "skipped" or updates:
        raise AssertionError(f"repaired kept passkey was written again: {outcome}")


def assert_strict_signature_ignores_marker() -> None:
    """Legacy REF output written before the marker still matches exactly."""
    unmarked = _desired([_credential(SOURCE_ID)])["login"]
    marked = _desired([_credential(MARKED_ID)])["login"]
    if Converter._strict_login_signature(unmarked) != Converter._strict_login_signature(
        marked
    ):
        raise AssertionError("credential ID marker changed the strict REF signature")


def supported_pem() -> str:
    """Deterministic synthetic P-256 fixture, never a real credential."""
    return (
        ec
        .derive_private_key(1, ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def source_properties() -> dict[str, str]:
    return {
        "KPEX_PASSKEY_CREDENTIAL_ID": SOURCE_ID,
        "KPEX_PASSKEY_PRIVATE_KEY_PEM": supported_pem(),
        "KPEX_PASSKEY_RELYING_PARTY": "example.com",
        "KPEX_PASSKEY_USER_HANDLE": "dXNlci1oYW5kbGU",
        "KPEX_PASSKEY_USERNAME": "alice",
    }


def verify_native_key(credential: BwFido2Credential) -> None:
    encoded = credential["keyValue"]
    key = serialization.load_der_private_key(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)), password=None
    )
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    challenge = b"kp2bw synthetic passkey round-trip"
    signature = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    ec.derive_private_key(1, ec.SECP256R1()).public_key().verify(
        signature, challenge, ec.ECDSA(hashes.SHA256())
    )


def assert_final_items_validate_and_preserve_sources() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "passkeys.kdbx"
        create_database(str(path), password="synthetic")
        database = PyKeePass(str(path), password="synthetic")

        def convert(
            properties: dict[str, str], *, oversize: bool = False
        ) -> tuple[BwItemCreate, list[object]]:
            entry = database.add_entry(
                database.root_group,
                f"Passkey {len(database.entries)}",
                "alice",
                "synthetic",
            )
            for index, (name, value) in enumerate(properties.items()):
                entry.set_custom_property(name, value, protect=index % 2 == 0)
            converter = _converter()
            converter._include_oversize_secrets = oversize
            converter._add_bw_entry_to_entries_dict(entry)
            result = next(iter(converter._entries.values()))
            return result[2], list(result[3])

        item, attachments = convert(source_properties())
        assert item["login"] is not None
        credentials = item["login"].get("fido2Credentials")
        assert credentials and credentials[0]["credentialId"] == MARKED_ID
        verify_native_key(credentials[0])
        assert not attachments
        assert not any(
            field["name"].startswith("KPEX_PASSKEY_") for field in item["fields"]
        )

        bad_properties: list[dict[str, str]] = []
        for name in (
            "KPEX_PASSKEY_CREDENTIAL_ID",
            "KPEX_PASSKEY_PRIVATE_KEY_PEM",
            "KPEX_PASSKEY_RELYING_PARTY",
            "KPEX_PASSKEY_USER_HANDLE",
        ):
            props = source_properties()
            del props[name]
            bad_properties.append(props)
        invalid_keys = [
            "-----BEGIN PRIVATE KEY-----\nAAE=\n-----END PRIVATE KEY-----",
            "a",
            supported_pem().replace("END PRIVATE KEY", "END PUBLIC KEY"),
            supported_pem().replace("PRIVATE KEY", "EC PRIVATE KEY"),
            ec
            .generate_private_key(ec.SECP384R1())
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode(),
            ed25519.Ed25519PrivateKey
            .generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode(),
        ]
        replacements = [
            ("KPEX_PASSKEY_PRIVATE_KEY_PEM", value) for value in invalid_keys
        ]
        replacements += [
            ("KPEX_PASSKEY_CREDENTIAL_ID", value)
            for value in ("a", "not an ID", "b64.", "AB")
        ]
        replacements += [
            ("KPEX_PASSKEY_USER_HANDLE", "a"),
            ("KPEX_PASSKEY_USER_HANDLE", "YQ" * 100),
            ("KPEX_PASSKEY_RELYING_PARTY", "https://example.com"),
        ]
        for name, value in replacements:
            bad_properties.append(source_properties() | {name: value})
        for props in bad_properties:
            item, attachments = convert(props)
            assert item["login"] is not None
            assert not item["login"].get("fido2Credentials")
            recovered = {
                field["name"]: field
                for field in item["fields"]
                if field["name"] in props
            }
            assert {name: field["value"] for name, field in recovered.items()} == props
            assert all(field["type"] == 1 for field in recovered.values())
            assert not attachments

        large = source_properties() | {"KPEX_PASSKEY_PRIVATE_KEY_PEM": "x" * 10001}
        item, attachments = convert(large)
        assert not attachments
        assert not any(
            field["name"] == "KPEX_PASSKEY_PRIVATE_KEY_PEM" for field in item["fields"]
        )
        _, attachments = convert(large, oversize=True)
        assert (
            "KPEX_PASSKEY_PRIVATE_KEY_PEM",
            large["KPEX_PASSKEY_PRIVATE_KEY_PEM"],
        ) in attachments


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_final_items_validate_and_preserve_sources()
    assert_base64url_credential_id_uses_bitwarden_marker()
    assert_existing_bitwarden_marker_is_preserved()
    assert_rerun_repairs_unmarked_credential_id()
    assert_repaired_passkey_item_is_idempotent()
    assert_bitwarden_passkey_edit_under_old_stamp_is_protected()
    assert_passkey_added_to_passkeyless_item_syncs()
    assert_bitwarden_native_passkey_is_not_protected()
    assert_bitwarden_only_passkey_survives_and_settles()
    assert_kept_unmarked_passkey_is_repaired()
    assert_strict_signature_ignores_marker()


if __name__ == "__main__":
    main()
