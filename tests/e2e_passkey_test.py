"""Verify native passkeys and recoverable failures through the real CLI."""

import uuid
from pathlib import Path
from typing import cast

from e2e_vaultwarden_test import _bw_json, _get_session, _run, _run_migration
from passkey_conversion_test import MARKED_ID, source_properties, verify_native_key
from pykeepass import create_database

from kp2bw.bw_types import BwItemResponse


def run_passkey_test(tmp: Path, env: dict[str, str], password: str) -> None:
    source = tmp / "passkeys.kdbx"
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
    session = _get_session(env, password)

    def read_cases() -> dict[str, BwItemResponse]:
        nonlocal session
        session = _get_session(env, password)
        _run(["bw", "sync", "--session", session], env=env)
        items = _bw_json(env, "list", "items", "--session", session)
        result: dict[str, BwItemResponse] = {}
        for case in cases:
            matches = [item for item in items if item.get("name") == f"{prefix} {case}"]
            assert len(matches) == 1, "Passkey fixture missing or duplicated"
            result[case] = cast(BwItemResponse, matches[0])
        return result

    try:
        _run_migration(source, kp_password, password, env)
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
        _run_migration(source, kp_password, password, env)
        second = read_cases()
        for case in cases:
            assert second[case]["id"] == first[case]["id"]
            assert second[case]["revisionDate"] == first[case]["revisionDate"], (
                "Unchanged passkey rewritten"
            )
    finally:
        session = _get_session(env, password)
        _run(["bw", "sync", "--session", session], env=env)
        for item in _bw_json(env, "list", "items", "--session", session):
            candidate = cast(BwItemResponse, item)
            if not str(candidate.get("name")).startswith(prefix):
                continue
            if any(
                field["name"] == "KP2BW_ID" and field["value"] in source_ids
                for field in candidate.get("fields") or []
            ):
                _run(
                    [
                        "bw",
                        "delete",
                        "item",
                        str(candidate["id"]),
                        "--permanent",
                        "--session",
                        session,
                    ],
                    env=env,
                )
    print("live passkey validation, recovery and idempotency regression passed")
