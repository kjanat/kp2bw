"""Keep reserved source fields through live migration and unchanged reruns."""

import uuid

from e2e_support import Vault, vault_main
from pykeepass import create_database
from reserved_fields_test import append_field

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.source_fields import source_field_name


def run_reserved_fields_test(vault: Vault) -> None:
    source = vault.tmp / "reserved-fields.kdbx"
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
        result: dict[str, BwItemResponse] = {}
        for candidate in vault.items():
            name = candidate.get("name")
            if name not in identities:
                continue
            assert name not in result, "Duplicated source item"
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

    def migrate() -> None:
        converter = Converter(
            str(source), kp_password, None, vault.password, None, None, False, 999, None
        )
        assert converter.convert(vault.client) == 0

    try:
        migrate()
        first = read_cases()
        migrate()
        second = read_cases()
        for name in identities:
            assert first[name]["id"] == second[name]["id"]
            assert first[name]["revisionDate"] == second[name]["revisionDate"], (
                "Unchanged source item rewritten"
            )
    finally:
        vault.delete_sources(set(identities.values()), identities.keys())
    print("live reserved-field preservation and idempotency regression passed")


def main() -> None:
    vault_main(run_reserved_fields_test)


if __name__ == "__main__":
    main()
