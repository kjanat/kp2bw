"""Live #69 regression against the disposable Vaultwarden fixture only."""

import os
import tempfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

from e2e_vaultwarden_test import bw_json, get_session, login_session, run
from pykeepass import create_database
from scope_fixture import create_scope_organization

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.bw_types import BwItemCreate, BwItemResponse
from kp2bw.item_sync import stamp_content


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
    org_id = create_scope_organization(server, cert, email, password)
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        env = os.environ.copy()
        env.update(
            BITWARDENCLI_APPDATA_DIR=str(tmp / "bw"),
            NODE_EXTRA_CA_CERTS=str(cert),
            KP2BW_BITWARDEN_PASSWORD=password,
        )
        run(["bw", "config", "server", server], env=env)
        login_session(env, email, password)
        source = tmp / "scope.kdbx"
        db = create_database(source, password="synthetic-keepass-password")
        entry = db.add_entry(
            db.root_group, "A imported", "source-user", "source-password"
        )
        db.save()
        with (
            patch.dict(os.environ, env),
            BitwardenServeClient(password, org_id=org_id) as bw,
        ):
            inside = bw.list_collections()["Scope A"]
            outside = bw.create_org_collection("Scope B")
            assert outside is not None
            ids: list[str] = []
            for name, collection in (("A original", inside), ("Z outside", outside)):
                item = cast(
                    BwItemResponse,
                    {
                        "name": name,
                        "type": 1,
                        "organizationId": org_id,
                        "collectionIds": [collection],
                        "login": {"username": "old", "password": "old", "uris": []},
                        "fields": [
                            {
                                "name": "KP2BW_ID",
                                "value": entry.uuid.hex.upper(),
                                "type": 0,
                            }
                        ],
                    },
                )
                stamp_content(item)
                ids.append(bw.create_item(cast(BwItemCreate, item)))

        def read_items() -> dict[str, BwItemResponse]:
            session = get_session(env, password)
            run(["bw", "sync", "--session", session], env=env)
            return {
                str(item["id"]): cast(BwItemResponse, item)
                for item in bw_json(env, "list", "items", "--session", session)
            }

        original = read_items()
        command = ["uv", "run", "kp2bw", "-o", org_id, "-c", inside, "-y"]
        import_command = [
            *command,
            str(source),
            "--keepass-password",
            "synthetic-keepass-password",
            "--path-to-name-skip",
            "999",
            "--no-metadata",
        ]
        run(import_command, env=env)
        imported = read_items()
        assert imported[ids[0]]["name"] == "A imported"
        assert imported[ids[1]] == original[ids[1]], (
            "Import changed the outside control"
        )
        run(import_command, env=env)
        assert read_items() == imported, "Unchanged scoped import wrote an item"

        # Seed distinct reporting domains and legacy fields after import, then
        # exercise the actual maintenance CLI, with revision-sensitive controls.
        with (
            patch.dict(os.environ, env),
            BitwardenServeClient(password, org_id=org_id) as bw,
        ):
            for item_id, domain in zip(
                ids, ("inside-scope.example", "outside-scope.example"), strict=True
            ):
                item = bw.get_item(item_id)
                item["fields"] = [
                    *(item.get("fields") or []),
                    {
                        "name": "KP2A_URL",
                        "value": f"https://legacy.{domain}",
                        "type": 0,
                    },
                ]
                login = item.get("login")
                assert login is not None
                login["uris"] = [
                    {"uri": f"https://{host}.{domain}", "match": 0}
                    for host in ("one", "two")
                ]
                stamp_content(item)
                bw.update_item(item_id, item)
        before = read_items()
        report = run([*command, "--report-uris", "bitwarden"], env=env)
        assert (
            "inside-scope.example" in report and "outside-scope.example" not in report
        )
        assert read_items() == before, "Reporting changed vault content"
        run([*command, "--migrate-uris"], env=env)
        migrated = read_items()
        assert migrated[ids[1]] == before[ids[1]], (
            "URI migration changed the outside control"
        )
        assert not any(
            f.get("name") == "KP2A_URL" for f in migrated[ids[0]].get("fields") or []
        )
        run([*command, "--migrate-uris"], env=env)
        assert read_items() == migrated, "Repeated URI migration wrote an item"
        run([*command, "--strip-ids"], env=env)
        stripped = read_items()
        assert stripped[ids[1]] == before[ids[1]], (
            "Finalization changed the outside control"
        )
        assert not any(
            f.get("name") in {"KP2BW_ID", "KP2BW_SYNC"}
            for f in stripped[ids[0]].get("fields") or []
        )
        run([*command, "--strip-ids"], env=env)
        assert read_items() == stripped, "Repeated finalization wrote an item"
    print("live organization/collection scope regression passed")


if __name__ == "__main__":
    main()
