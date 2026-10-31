"""Round-trip encrypted field boundaries in personal and organization vaults."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from e2e_vaultwarden_test import login_session, run
from pykeepass import create_database
from scope_fixture import create_scope_organization

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
            VW_APPDATA_DIR=str(tmp / "bw"),
            NODE_EXTRA_CA_CERTS=str(cert),
            BW_NOINTERACTION="true",
        )
        run(["bw", "config", "server", server], env=env)
        login_session(env, email, password)
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
                metadata_entry = db.add_entry(
                    db.root_group, "Metadata collision", "user", "pw"
                )
                metadata_entry.tags = ["é" * 4000]
                metadata_entry.add_attachment(
                    db.add_binary(b"original metadata file"), "KP2BW_META.txt"
                )
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
                metadata_ids: set[str] = set()
                for rerun in (False, True):
                    if rerun:
                        migrate()
                    with BitwardenServeClient(password, org_id=organization) as bw:
                        meta = bw.get_item_by_uuid(metadata_entry.uuid.hex.upper())
                        assert meta is not None
                        meta = bw.get_item(meta["id"])
                        files = meta.get("attachments") or []
                        assert (
                            len(files) == 2 and len({a["fileName"] for a in files}) == 2
                        )
                        contents = {
                            a["fileName"]: bw.get_attachment(meta["id"], a["id"])
                            for a in files
                        }
                        assert (
                            contents.pop("KP2BW_META.txt") == b"original metadata file"
                        )
                        assert (
                            json.loads(next(iter(contents.values())))["tags"]
                            == metadata_entry.tags
                        )
                        ids = {a["id"] for a in files}
                        if rerun:
                            assert ids == metadata_ids
                            assert (
                                meta.get("revisionDate")
                                == revisions[metadata_entry.uuid.hex.upper()]
                            )
                            bw.request("DELETE", f"/object/item/{meta['id']}")
                        else:
                            metadata_ids = ids
                            revisions[metadata_entry.uuid.hex.upper()] = meta.get(
                                "revisionDate"
                            )
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
                                bw.request("DELETE", f"/object/item/{item['id']}")
                            else:
                                revisions[source_id] = revision
    print("personal and organization field boundary round trips passed")


if __name__ == "__main__":
    main()
