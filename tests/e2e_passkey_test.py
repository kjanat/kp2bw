"""Verify native passkeys and recoverable failures through the real CLI."""

import uuid

from e2e_support import Vault, vault_main
from passkey_conversion_test import MARKED_ID, source_properties, verify_native_key
from pykeepass import create_database

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter


def run_passkey_test(vault: Vault) -> None:
    source = vault.tmp / "passkeys.kdbx"
    kp_password = "SyntheticPasskeyPassword123!"
    database = create_database(source, password=kp_password)
    prefix = f"Passkey {uuid.uuid4().hex}"
    source_ids: set[str] = set()
    cases = {
        "valid": source_properties(),
        "invalid": source_properties() | {"KPEX_PASSKEY_PRIVATE_KEY_PEM": "a"},
    }
    for case, properties in cases.items():
        entry = database.add_entry(
            database.root_group, f"{prefix} {case}", "alice", "synthetic"
        )
        source_ids.add(entry.uuid.hex.upper())
        for name, value in properties.items():
            entry.set_custom_property(name, value, protect=True)
    database.save()

    def read_cases() -> dict[str, BwItemResponse]:
        named = vault.named(*(f"{prefix} {case}" for case in cases))
        return {case: named[f"{prefix} {case}"] for case in cases}

    def migrate() -> None:
        converter = Converter(
            str(source),
            kp_password,
            None,
            vault.password,
            None,
            None,
            False,
            999,
            None,
            migrate_metadata=False,
        )
        assert converter.convert(vault.client) == 0

    try:
        vault.migrate(source, kp_password)
        first = read_cases()
        login = first["valid"].get("login")
        assert login is not None
        credentials = login.get("fido2Credentials")
        assert credentials and credentials[0]["credentialId"] == MARKED_ID
        verify_native_key(credentials[0])
        invalid = first["invalid"]
        invalid_login = invalid.get("login")
        assert invalid_login is not None
        assert not invalid_login.get("fido2Credentials")
        recovered = {
            field["name"]: field
            for field in invalid.get("fields") or []
            if field["name"] in cases["invalid"]
        }
        assert {name: field["value"] for name, field in recovered.items()} == cases[
            "invalid"
        ]
        assert all(field["type"] == 1 for field in recovered.values())
        migrate()
        second = read_cases()
        for case in cases:
            assert second[case]["id"] == first[case]["id"]
            assert second[case]["revisionDate"] == first[case]["revisionDate"], (
                "Unchanged passkey rewritten"
            )
    finally:
        vault.delete_sources(source_ids, {f"{prefix} {case}" for case in cases})
    print("live passkey validation, recovery and idempotency regression passed")


def main() -> None:
    vault_main(run_passkey_test)


if __name__ == "__main__":
    main()
