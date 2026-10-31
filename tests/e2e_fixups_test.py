"""Run registered fixups through the CLI against a disposable Vaultwarden server."""

import copy
import json
from typing import cast

from e2e_support import Vault, vault_main

from kp2bw.bw_serve import item_kp2bw_sync
from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.fixups import FixupOptions, FixupResult, run_fixups
from kp2bw.item_sync import stamp_content, sync_stamp_matches
from kp2bw.uri_mapping import parse_match_name

LEGACY = "expires: '2040-01-01T00:00:00+00:00'\ntags:\n- café\n- two\n"


def run_fixups_test(vault: Vault) -> None:
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

    def read() -> dict[str, BwItemResponse]:
        fresh = vault.fresh()
        return {case: fresh.get_item(item_id) for case, item_id in ids.items()}

    def command(*args: str, expected: int = 0) -> str:
        result = vault.kp2bw(*args, "-y", expected=expected, env=env)
        return result.stdout + result.stderr

    def fixup(org_id: str | None, collection_id: str | None) -> FixupResult:
        return run_fixups(
            bw,
            org_id=org_id,
            collection_id=collection_id,
            options=FixupOptions(parse_match_name("default"), True),
        )

    def meta(item: BwItemResponse) -> str:
        return next(
            field["value"] or ""
            for field in item["fields"]
            if field["name"] == "KP2BW_META"
        )

    try:
        before = read()
        output = command("--fixup", "-o", org, "-c", inside, expected=1)
        assert "4 scanned, 2 migrated, 1 skipped, 1 failed" in output
        after = read()
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
        repeated = fixup(org, inside)
        assert repeated.migrated == 0 and repeated.failed and read() == after
        command("--migrate-uris", "-o", org, "-c", outside)
        uri_only = read()
        assert meta(uri_only["outside"]) == LEGACY, "URI-only mode ran metadata fixup"
        assert not any(
            field["name"] == "KP2A_URL" for field in uri_only["outside"]["fields"]
        )
        assert not fixup(None, None).failed
        personal = read()
        assert json.loads(meta(personal["personal"]))["tags"] == ["café", "two"]
        for case in ids:
            if case != "personal":
                assert personal[case] == uri_only[case], (
                    "Personal fixup changed an organization item"
                )
        snapshot = copy.deepcopy(personal)
        assert not fixup(None, None).failed
        assert read() == snapshot
    finally:
        for item_id in ids.values():
            bw.request("DELETE", f"/object/item/{item_id}")
    print("live fixup scope, metadata, URI compatibility, protection and reruns passed")


def main() -> None:
    vault_main(run_fixups_test)


if __name__ == "__main__":
    main()
