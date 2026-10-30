"""Encrypted field boundaries and final conversion routing."""

import base64
import hashlib
import hmac
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from pykeepass import create_database

from kp2bw._field_limits import encrypted_length, validate_item
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError, FieldLimitError


def encrypt_fixture(text: str) -> str:
    key, iv = bytes(range(32)), bytes(range(16))
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(  # pyright: ignore[reportUnknownMemberType]
        pad(text.encode(), AES.block_size)
    )
    mac = hmac.digest(key, iv + ciphertext, hashlib.sha256)
    return "2." + "|".join(
        base64.b64encode(part).decode() for part in (iv, ciphertext, mac)
    )


def converter(organization: str | None = None, *, secrets: bool = False) -> Converter:
    return Converter(
        keepass_file_path="synthetic.kdbx",
        keepass_password="synthetic",
        keepass_keyfile_path=None,
        bitwarden_password="synthetic",
        bitwarden_organization_id=organization,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
        include_oversize_secrets=secrets,
    )


def main() -> None:
    for limit, boundary in ((1000, 687), (5000, 3695), (10000, 7439)):
        for count in (boundary - 1, boundary, boundary + 1):
            for value in ("a" * count, "é" * (count // 2) + "a" * (count % 2)):
                actual = len(encrypt_fixture(value))
                assert actual == encrypted_length(value)
                assert (actual <= limit) == (count <= boundary)

    with tempfile.TemporaryDirectory() as directory:
        database = create_database(
            Path(directory) / "limits.kdbx", password="synthetic"
        )
        for organization in (None, "00000000-0000-0000-0000-000000000001"):
            for size in (3694, 3695, 3696):
                entry = database.add_entry(
                    database.root_group, f"Field {organization} {size}", "user", "pw"
                )
                entry.set_custom_property("value", "x" * size)
                conv = converter(organization)
                conv._add_bw_entry_to_entries_dict(entry)
                _, _, item, attachments = next(iter(conv._entries.values()))
                fields = {field["name"]: field["value"] for field in item["fields"]}
                assert ("value" in fields) == (size <= 3695)
                assert (
                    ("value.txt", ("x" * size).encode())
                    in [conv._materialise_attachment(a) for a in attachments]
                ) == (size > 3695)

            for size in (7438, 7439, 7440):
                entry = database.add_entry(
                    database.root_group, f"Notes {organization} {size}", "user", "pw"
                )
                entry.notes = "é" * (size // 2) + "x" * (size % 2)
                conv = converter(organization)
                conv._add_bw_entry_to_entries_dict(entry)
                _, _, item, attachments = next(iter(conv._entries.values()))
                assert (item["notes"] == entry.notes) == (size <= 7439)
                assert (
                    ("notes.txt", (entry.notes or "").encode())
                    in [conv._materialise_attachment(a) for a in attachments]
                ) == (size > 7439)

            for member, boundary in (
                ("title", 687),
                ("username", 687),
                ("password", 3695),
            ):
                for size in (boundary - 1, boundary, boundary + 1):
                    entry = database.add_entry(
                        database.root_group,
                        f"Required {organization} {member} {size}",
                        "user",
                        "pw",
                    )
                    setattr(entry, member, "é" * (size // 2) + "z" * (size % 2))
                    conv = converter(organization)
                    try:
                        conv._add_bw_entry_to_entries_dict(entry)
                    except ConversionError as exc:
                        assert size > boundary
                        assert "z" * 50 not in str(exc), (
                            "Diagnostic exposed source content"
                        )
                    else:
                        assert size <= boundary

        group = database.add_group(database.root_group, "Group")
        for size in (679, 680):
            entry = database.add_entry(group, "x" * size, "user", "pw")
            conv = converter()
            conv._path2name = True
            conv._path2nameskip = 0
            try:
                conv._add_bw_entry_to_entries_dict(entry)
            except ConversionError:
                assert size == 680
            else:
                assert size == 679
        for size in (7429, 7430):
            entry = database.add_entry(
                database.root_group, f"Expired {size}", "user", "pw"
            )
            entry.expires = True
            entry.expiry_time = datetime(2000, 1, 1, tzinfo=UTC)
            entry.notes = "n" * size
            conv = converter()
            conv._add_bw_entry_to_entries_dict(entry)
            _, _, item, attachments = next(iter(conv._entries.values()))
            assert item["notes"] == (
                "[EXPIRED] " + (entry.notes or "") if size == 7429 else "[EXPIRED] "
            )
            assert bool(attachments) == (size == 7430)
        for size in (7438, 7439, 7440):
            entry = database.add_entry(database.root_group, f"URI {size}", "user", "pw")
            uri = "https://example.com/" + "x" * (size - len("https://example.com/"))
            assert len(uri) == size
            entry.set_custom_property("KP2A_URL", uri)
            conv = converter()
            try:
                conv._add_bw_entry_to_entries_dict(entry)
            except ConversionError:
                assert size == 7440
            else:
                assert size <= 7439
                assert not next(iter(conv._entries.values()))[3], (
                    "Native URI also offloaded"
                )
        entry = database.add_entry(database.root_group, "Secret", "user", "pw")
        entry.set_custom_property("secret", "é" * 2000, protect=True)
        for allowed in (False, True):
            conv = converter(secrets=allowed)
            conv._add_bw_entry_to_entries_dict(entry)
            _, _, item, attachments = next(iter(conv._entries.values()))
            assert not any(field["name"] == "secret" for field in item["fields"])
            assert bool(attachments) == allowed
        entry = database.add_entry(database.root_group, "Metadata", "user", "pw")
        entry.tags = ["é" * 4000]
        conv = converter()
        conv._add_bw_entry_to_entries_dict(entry)
        _, _, item, attachments = next(iter(conv._entries.values()))
        assert not any(field["name"] == "KP2BW_META" for field in item["fields"])
        assert any(
            conv._attachment_filename(attachment) == "KP2BW_META.txt"
            for attachment in attachments
        )
        assert (
            json.loads(conv._materialise_attachment(attachments[0])[1])["tags"]
            == entry.tags
        )
        for size in (686, 687, 688):
            entry = database.add_entry(database.root_group, f"Names {size}", "u", "p")
            entry.set_custom_property("n" * size, "v")
            conv = converter()
            try:
                conv._add_bw_entry_to_entries_dict(entry)
            except ConversionError:
                assert size == 688
            else:
                assert size <= 687
                item = next(iter(conv._entries.values()))[2]
                item["login"]["totp"] = "x" * size
                validate_item(item)
                item["login"]["totp"] = "x" * 688
                try:
                    validate_item(item)
                except ConversionError:
                    pass
                else:
                    raise AssertionError("Oversized native TOTP accepted")
        # A bad required value anywhere in the source must prevent all writes.
        database.add_entry(database.root_group, "x" * 688, "user", "pw")
        database.save()
        conv = converter()
        conv._keepass_file_path = str(Path(directory) / "limits.kdbx")
        with patch.object(Converter, "_create_bitwarden_items_for_entries") as write:
            try:
                conv.convert()
            except ConversionError:
                pass
            else:
                raise AssertionError("Preflight accepted an oversized title")
            write.assert_not_called()
    # REF-created items must fail preflight just like ordinary items. Exercise
    # credential mismatch and matching credentials with extra alias content.
    for member, size in (("title", 688), ("username", 688), ("password", 3696)):
        for chained in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "refs.kdbx"
                database = create_database(path, password="synthetic")
                target = database.add_entry(database.root_group, "Target", "u", "p")
                reference = f"{{REF:P@I:{target.uuid.hex.upper()}}}"
                alias = database.add_entry(database.root_group, "Alias", "u", reference)
                if member == "password":
                    alias.username = f"{{REF:U@I:{target.uuid.hex.upper()}}}"
                setattr(alias, member, "x" * size)
                alias.notes = "Keep this alias separate even with matching credentials."
                if chained:
                    parent = database.add_entry(
                        database.root_group,
                        "Parent",
                        "u",
                        f"{{REF:P@I:{alias.uuid.hex.upper()}}}",
                    )
                    # Force the parent to resolve the invalid child recursively.
                    parent.uuid = UUID(int=1)
                    alias.uuid = UUID(int=2)
                    parent.password = f"{{REF:P@I:{alias.uuid.hex.upper()}}}"
                database.save()
                conv = converter()
                conv._keepass_file_path = str(path)
                with patch.object(
                    Converter, "_create_bitwarden_items_for_entries"
                ) as write:
                    try:
                        conv.convert()
                    except FieldLimitError:
                        pass
                    else:
                        raise AssertionError(f"REF {member} failure was swallowed")
                    write.assert_not_called()
    print("encrypted field boundary and routing tests passed")


if __name__ == "__main__":
    main()
