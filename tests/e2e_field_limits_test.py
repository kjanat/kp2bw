"""Round-trip encrypted field boundaries in personal and organization vaults."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from _scope_fixture import create_scope_organization
from e2e_vaultwarden_test import _login_session, _run
from pykeepass import create_database

from kp2bw.bw_serve import BitwardenServeClient
from kp2bw.convert import Converter


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
            BW_NOINTERACTION="true",
        )
        _run(["bw", "config", "server", server], env=env)
        _login_session(env, email, password)
        with patch.dict(os.environ, env):
            for organization in (None, org_id):
                source = tmp / f"limits-{organization}.kdbx"
                db = create_database(source, password="synthetic")
                expected: dict[str, tuple[str, str, str]] = {}
                for delta in (-1, 0, 1):
                    title = str(delta) + "é" * 341
                    entry = db.add_entry(
                        db.root_group, title, "é" * 343 + "x", "é" * 1847 + "x"
                    )
                    value = "é" * ((3695 + delta) // 2) + "x" * ((3695 + delta) % 2)
                    notes = "é" * ((7439 + delta) // 2) + "x" * ((7439 + delta) % 2)
                    entry.notes = notes
                    entry.set_custom_property("value", value)
                    expected[entry.uuid.hex.upper()] = (title, value, notes)
                db.save()
                with BitwardenServeClient(password, org_id=organization) as bw:
                    collection = (
                        bw.list_collections()["Scope A"] if organization else None
                    )

                def migrate(
                    source: Path = source,
                    organization: str | None = organization,
                    collection: str | None = collection,
                ) -> None:
                    conv = Converter(
                        keepass_file_path=str(source),
                        keepass_password="synthetic",
                        keepass_keyfile_path=None,
                        bitwarden_password=password,
                        bitwarden_organization_id=organization,
                        bitwarden_coll_id=collection,
                        path2name=False,
                        path2nameskip=999,
                        import_tags=None,
                    )
                    assert conv.convert() == 0

                migrate()
                revisions: dict[str, str | None] = {}
                for rerun in (False, True):
                    if rerun:
                        migrate()
                    with BitwardenServeClient(password, org_id=organization) as bw:
                        for source_id, (title, value, notes) in expected.items():
                            item = bw.get_item_by_uuid(source_id)
                            assert item is not None
                            full = bw.get_item(item["id"])
                            assert full["name"] == title
                            assert full.get("organizationId") == organization
                            login = full.get("login")
                            assert login is not None
                            assert login["username"] == "é" * 343 + "x"
                            assert login["password"] == "é" * 1847 + "x"
                            fields = {
                                field["name"]: field["value"]
                                for field in full["fields"]
                            }
                            offloaded = len(value.encode()) > 3695
                            assert fields.get("value") == (None if offloaded else value)
                            assert full["notes"] == ("" if offloaded else notes)
                            attachments = full.get("attachments") or []
                            assert len(attachments) == (2 if offloaded else 0)
                            for attachment in attachments:
                                wanted = {"notes.txt": notes, "value.txt": value}[
                                    attachment["fileName"]
                                ]
                                assert (
                                    bw.get_attachment(item["id"], attachment["id"])
                                    == wanted.encode()
                                )
                            revision = full.get("revisionDate")
                            if rerun:
                                assert revision == revisions[source_id]
                                bw._request("DELETE", f"/object/item/{item['id']}")
                            else:
                                revisions[source_id] = revision
    print("personal and organization field boundary round trips passed")


if __name__ == "__main__":
    main()
