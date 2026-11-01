"""Run registered fixups through the CLI against a disposable Vaultwarden server."""

import copy
import json
from dataclasses import dataclass
from typing import cast

from e2e_support import Vault, vault_main

from kp2bw.bw_serve import item_kp2bw_sync
from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.fixups import FixupOptions, run_fixups
from kp2bw.item_sync import stamp_content, sync_stamp_matches
from kp2bw.uri_mapping import parse_match_name

LEGACY = "expires: '2040-01-01T00:00:00+00:00'\ntags:\n- café\n- two\n"


@dataclass
class FixupFixture:
    vault: Vault
    org: str
    inside: str
    outside: str
    ids: dict[str, str]
    env: dict[str, str]

    def read(self) -> dict[str, BwItemResponse]:
        fresh = self.vault.fresh()
        return {case: fresh.get_item(item_id) for case, item_id in self.ids.items()}

    def command(self, *args: str, expected: int = 0) -> str:
        result = self.vault.kp2bw(
            *args,
            "-y",
            expected=expected,
            env=self.env,
            unset=("KP2BW_KEEPASS_FILE", "KP2BW_KEEPASS_PASSWORD"),
        )
        return result.stdout + result.stderr

    def delete(self) -> None:
        self.vault.delete(*self.ids.values())


def meta(item: BwItemResponse) -> str:
    return next(
        field["value"] or ""
        for field in item["fields"]
        if field["name"] == "KP2BW_META"
    )


def fixup_fixture(vault: Vault) -> FixupFixture:
    password = vault.password
    org = vault.organization()
    inside = vault.collections(org)["Scope A"]
    bw = vault.client
    env = {"KP2BW_BITWARDEN_PASSWORD": password}
    ids: dict[str, str] = {}
    with bw.scope(org, inside):
        outside = bw.create_org_collection("Outside fixup")
    assert outside is not None
    for case in (
        "stamped",
        "legacy",
        "edited",
        "invalid",
        "outside",
        "personal",
    ):
        personal = case == "personal"
        item = cast(
            BwItemResponse,
            {
                "name": f"Fixup {case}",
                "type": 1,
                "notes": None,
                "favorite": False,
                "organizationId": None if personal else org,
                "collectionIds": []
                if personal
                else [outside if case == "outside" else inside],
                "login": {
                    "username": "user",
                    "password": "password",
                    "uris": [],
                },
                "fields": [
                    {
                        "name": "KP2BW_META",
                        "value": "future: preserve" if case == "invalid" else LEGACY,
                        "type": 0,
                    },
                    {
                        "name": "KP2A_URL",
                        "value": "https://fixup.example",
                        "type": 0,
                    },
                ],
            },
        )
        if case != "legacy":
            stamp_content(item)
        if case == "edited":
            item["notes"] = "manual destination edit"
        ids[case] = bw.create_item(cast(BwItemCreate, item))
    return FixupFixture(vault, org, inside, outside, ids, env)


def run_fixups_test(vault: Vault) -> None:
    fixture = fixup_fixture(vault)
    org, inside = fixture.org, fixture.inside
    try:
        before = fixture.read()
        output = fixture.command("--fixup", "-o", org, "-c", inside, expected=1)
        assert "4 scanned, 2 migrated, 1 skipped, 1 failed" in output
        after = fixture.read()
        for case in ("stamped", "legacy"):
            assert json.loads(meta(after[case])) == {
                "expires": "2040-01-01T00:00:00+00:00",
                "tags": ["café", "two"],
            }
            assert not any(
                field["name"] == "KP2A_URL" for field in after[case]["fields"]
            )
            login = after[case].get("login")
            assert login is not None
            assert any(uri["uri"] == "https://fixup.example" for uri in login["uris"])
            stamp = item_kp2bw_sync(after[case])
            assert stamp and sync_stamp_matches(after[case], stamp)
        for case in ("edited", "invalid", "outside", "personal"):
            assert after[case] == before[case], f"Fixup changed {case} control"
        output = fixture.command("--fixup", "-o", org, "-c", inside, expected=1)
        assert "0 migrated" in output and fixture.read() == after
    finally:
        fixture.delete()
    print("live organization fixup, protection and rerun passed")


def run_fixups_uri_only_test(vault: Vault) -> None:
    fixture = fixup_fixture(vault)
    try:
        fixture.command("--migrate-uris", "-o", fixture.org, "-c", fixture.outside)
        uri_only = fixture.read()
        assert meta(uri_only["outside"]) == LEGACY, "URI-only mode ran metadata fixup"
        assert not any(
            field["name"] == "KP2A_URL" for field in uri_only["outside"]["fields"]
        )
    finally:
        fixture.delete()
    print("live URI-only maintenance without metadata fixup passed")


def run_fixups_personal_test(vault: Vault) -> None:
    fixture = fixup_fixture(vault)
    try:
        before = fixture.read()
        fixture.command("--fixup")
        personal = fixture.read()
        assert json.loads(meta(personal["personal"]))["tags"] == ["café", "two"]
        for case in fixture.ids:
            if case != "personal":
                assert personal[case] == before[case], (
                    "Personal fixup changed an organization item"
                )
        snapshot = copy.deepcopy(personal)
        repeated = run_fixups(
            vault.client,
            options=FixupOptions(parse_match_name("default"), True),
        )
        assert not repeated.failed
        assert fixture.read() == snapshot
    finally:
        fixture.delete()
    print("live personal fixup and rerun passed")


def main() -> None:
    def run_all(vault: Vault) -> None:
        run_fixups_test(vault)
        run_fixups_uri_only_test(vault)
        run_fixups_personal_test(vault)

    vault_main(run_all)


if __name__ == "__main__":
    main()
