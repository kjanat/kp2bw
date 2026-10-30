"""Keep reserved source fields through live migration and unchanged reruns."""

import uuid
from pathlib import Path
from typing import cast

from e2e_vaultwarden_test import bw_json, get_session, run, run_migration
from pykeepass import create_database
from reserved_fields_test import append_field

from kp2bw.bw_types import BwItemResponse
from kp2bw.source_fields import source_field_name


def run_reserved_fields_test(tmp: Path, env: dict[str, str], password: str) -> None:
    source = tmp / "reserved-fields.kdbx"
    kp_password = "SyntheticReservedFields123!"
    database = create_database(source, password=kp_password)
    prefix = f"Reserved {uuid.uuid4().hex}"
    identities: dict[str, str] = {}
    expected: dict[str, tuple[str, int]] = {}
    for metadata in (False, True):
        name = f"{prefix} {metadata}"
        entry = database.add_entry(database.root_group, name, "user", "synthetic")
        identities[name] = entry.uuid.hex.upper()
        if metadata:
            entry.tags = ["generated tag"]
        for key in ("KP2BW_ID", "KP2BW_SYNC", "KP2BW_META", "KeePass:KP2BW_ID:1"):
            for occurrence, protected in enumerate((False, True), start=1):
                value = f"synthetic {key} {occurrence}"
                append_field(entry, key, value, protected)
                expected[source_field_name(key, occurrence)] = (value, int(protected))
    database.save()

    def read_cases() -> dict[str, BwItemResponse]:
        session = get_session(env, password)
        run(["bw", "sync", "--session", session], env=env)
        result: dict[str, BwItemResponse] = {}
        for item in bw_json(env, "list", "items", "--session", session):
            candidate = cast(BwItemResponse, item)
            name = candidate.get("name")
            if name not in identities:
                continue
            assert name is not None and name not in result, "Duplicated source item"
            fields = candidate.get("fields") or []
            field_map = {field["name"]: field for field in fields}
            assert len(fields) == len(field_map), "Duplicated field names"
            assert field_map["KP2BW_ID"]["value"] == identities[name]
            for escaped, (value, field_type) in expected.items():
                assert field_map[escaped]["value"] == value
                assert field_map[escaped]["type"] == field_type
            result[name] = candidate
        assert result.keys() == identities.keys(), "Missing source item"
        return result

    try:
        run_migration(source, kp_password, password, env, metadata=True)
        first = read_cases()
        run_migration(source, kp_password, password, env, metadata=True)
        second = read_cases()
        for name in identities:
            assert first[name]["id"] == second[name]["id"]
            assert first[name]["revisionDate"] == second[name]["revisionDate"], (
                "Unchanged source item rewritten"
            )
    finally:
        session = get_session(env, password)
        run(["bw", "sync", "--session", session], env=env)
        for item in bw_json(env, "list", "items", "--session", session):
            candidate = cast(BwItemResponse, item)
            if candidate.get("name") not in identities:
                continue
            if any(
                field["name"] == "KP2BW_ID" and field["value"] in identities.values()
                for field in candidate.get("fields") or []
            ):
                run(
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
    print("live reserved-field preservation and idempotency regression passed")
