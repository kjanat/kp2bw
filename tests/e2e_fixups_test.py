"""Run registered fixups through the CLI against a disposable Vaultwarden server."""

import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

from e2e_vaultwarden_test import login_session, run
from scope_fixture import create_scope_organization

from kp2bw.bw_serve import BitwardenServeClient, item_kp2bw_sync
from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.item_sync import stamp_content, sync_stamp_matches

LEGACY = "expires: '2040-01-01T00:00:00+00:00'\ntags:\n- café\n- two\n"


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    cert = Path(
        os.environ.get(
            "BW_CERT_PATH", str(root / "tests/fixtures/vaultwarden-certs/cert.pem")
        )
    )
    email = os.environ.get("BW_TEST_EMAIL", "integration@example.com")
    password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    org = create_scope_organization(server, cert, email, password)
    with tempfile.TemporaryDirectory() as directory:
        env = os.environ.copy()
        env.update(
            BITWARDENCLI_APPDATA_DIR=str(Path(directory) / "profile"),
            VW_APPDATA_DIR=str(Path(directory) / "profile"),
            NODE_EXTRA_CA_CERTS=str(cert),
            BW_NOINTERACTION="true",
            KP2BW_BITWARDEN_PASSWORD=password,
        )
        env.pop("KP2BW_KEEPASS_FILE", None)
        env.pop("KP2BW_KEEPASS_PASSWORD", None)
        run(["bw", "config", "server", server], env=env)
        login_session(env, email, password)
        ids: dict[str, str] = {}
        with (
            patch.dict(os.environ, env),
            BitwardenServeClient(password, org_id=org) as bw,
        ):
            inside = bw.list_collections()["Scope A"]
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
                                "value": "future: preserve"
                                if case == "invalid"
                                else LEGACY,
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
            with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
                return {case: bw.get_item(item_id) for case, item_id in ids.items()}

        def command(*args: str, expected: int = 0) -> str:
            result = subprocess.run(
                ["uv", "run", "kp2bw", *args, "-y"],
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            assert result.returncode == expected, (
                f"Fixup command returned {result.returncode}, expected {expected}"
            )
            return result.stdout + result.stderr

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
                assert any(
                    uri["uri"] == "https://fixup.example" for uri in login["uris"]
                )
                stamp = item_kp2bw_sync(after[case])
                assert stamp and sync_stamp_matches(after[case], stamp)
            for case in ("edited", "invalid", "outside", "personal"):
                assert after[case] == before[case], f"Fixup changed {case} control"
            output = command("--fixup", "-o", org, "-c", inside, expected=1)
            assert "0 migrated" in output and read() == after
            command("--migrate-uris", "-o", org, "-c", outside)
            uri_only = read()
            assert meta(uri_only["outside"]) == LEGACY, (
                "URI-only mode ran metadata fixup"
            )
            assert not any(
                field["name"] == "KP2A_URL" for field in uri_only["outside"]["fields"]
            )
            command("--fixup")
            personal = read()
            assert json.loads(meta(personal["personal"]))["tags"] == ["café", "two"]
            for case in ids:
                if case != "personal":
                    assert personal[case] == uri_only[case], (
                        "Personal fixup changed an organization item"
                    )
            snapshot = copy.deepcopy(personal)
            command("--fixup")
            assert read() == snapshot
        finally:
            with patch.dict(os.environ, env), BitwardenServeClient(password) as bw:
                for item_id in ids.values():
                    bw.request("DELETE", f"/object/item/{item_id}")
    print("live fixup scope, metadata, URI compatibility, protection and reruns passed")


if __name__ == "__main__":
    main()
