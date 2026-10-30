"""Historical password transitions and recoverable, deterministic archives."""

import base64
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from lxml import etree
from pykeepass import PyKeePass, create_database

from kp2bw._attachments import SourceFile
from kp2bw._history import history_archive, native_password_history
from kp2bw.convert import Converter
from kp2bw.exceptions import ConversionError


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "history.kdbx"
        db = create_database(path, password="test")
        entry = db.add_entry(db.root_group, "History", "user", "first")
        assert native_password_history(entry) == []
        assert history_archive(entry, db.binaries) is None

        entry.ctime = datetime(2010, 1, 1, tzinfo=UTC)
        entry.atime = datetime(2011, 1, 1, tzinfo=UTC)
        old_bytes = b"historical attachment\x00\xff"
        ref = db.add_binary(old_bytes)
        attachment = entry.add_attachment(ref, "historical.dat")
        entry.notes = "old notes"
        entry.set_custom_property(
            "protected old value", "historical secret", protect=True
        )
        versions = [
            "first",
            "first",
            "second",
            "third",
            "second",
            "fourth",
            "fifth",
            "sixth",
            "seventh",
        ]
        for day, password in enumerate(versions, start=1):
            entry.password = password
            entry.mtime = datetime(2020, 1, day, tzinfo=UTC)
            entry.save_history()
        entry.password = "current"
        entry.mtime = datetime(2020, 1, 10, tzinfo=UTC)
        entry.notes = "current notes"
        entry.delete_attachment(attachment)
        entry.set_custom_property("protected old value", "current secret", protect=True)
        expected = [
            {"password": password, "lastUsedDate": f"2020-01-{day:02d}T00:00:00.000Z"}
            for password, day in [
                ("seventh", 10),
                ("sixth", 9),
                ("fifth", 8),
                ("fourth", 7),
                ("second", 6),
            ]
        ]
        assert native_password_history(entry) == expected
        archive = history_archive(entry, db.binaries)
        assert (
            archive is not None
            and archive.records == 9
            and archive.missing_binaries == 0
        )
        assert history_archive(entry, db.binaries) == archive
        document = json.loads(archive.data)
        assert document["entry_uuid"] == str(entry.uuid)
        recovered = document["binaries"][str(ref)]
        assert base64.b64decode(recovered["base64"]) == old_bytes
        assert recovered["sha256"] == hashlib.sha256(old_bytes).hexdigest()
        record = document["records"][0]
        assert record["created"] == "2010-01-01T00:00:00.000Z"
        assert record["modified"] == "2020-01-01T00:00:00.000Z"
        root = etree.fromstring(record["xml"].encode())
        fields = {
            field.findtext("Key"): field.find("Value")
            for field in root.findall("String")
        }
        note = fields["Notes"]
        protected = fields["protected old value"]
        reference = root.find("Binary/Value")
        assert note is not None and protected is not None and reference is not None
        assert note.text == "old notes"
        assert protected.get("Protected") == "True"
        assert protected.text == "historical secret"
        assert reference.get("Ref") == str(ref)

        # A saved/reopened database must preserve values, chronology and bytes.
        db.save()
        reopened = PyKeePass(path, password="test")
        restored = reopened.entries[0]
        assert native_password_history(restored) == expected
        reopened_archive = history_archive(restored, reopened.binaries)
        assert reopened_archive is not None
        assert history_archive(restored, reopened.binaries) == reopened_archive
        reopened_document = json.loads(reopened_archive.data)
        assert reopened_document["binaries"] == document["binaries"]
        assert len(reopened_document["records"]) == len(document["records"])
        for before, after in zip(
            document["records"], reopened_document["records"], strict=True
        ):
            before_xml, after_xml = before.pop("xml"), after.pop("xml")
            assert before == after
            parser = etree.XMLParser(remove_blank_text=True)
            assert etree.tostring(
                etree.fromstring(before_xml.encode(), parser)
            ) == etree.tostring(etree.fromstring(after_xml.encode(), parser))

        # Reusing an old password must not place the current password in history.
        entry.password = "second"
        result = native_password_history(entry)
        assert all(record["password"] != "second" for record in result)
        assert len({record["password"] for record in result}) == len(result) == 5

        # Note-only changes do not become artificial password-change dates.
        small = db.add_entry(db.root_group, "Notes", "user", "a")
        for day in (1, 2):
            small.mtime = datetime(2020, 2, day, tzinfo=UTC)
            small.notes = f"notes {day}"
            small.save_history()
        small.password = "b"
        small.mtime = datetime(2020, 2, 3, tzinfo=UTC)
        assert native_password_history(small) == [
            {"password": "a", "lastUsedDate": "2020-02-03T00:00:00.000Z"}
        ]
        small.mtime = datetime(2019, 1, 1, tzinfo=UTC)
        try:
            native_password_history(small)
        except ConversionError:
            pass
        else:
            raise AssertionError("History newer than current entry was accepted")

        # Missing original bytes are explicit, with the complete reference kept.
        incomplete = history_archive(entry, [])
        assert incomplete is not None and incomplete.missing_binaries == 1
        assert json.loads(incomplete.data)["binaries"][str(ref)] == {"available": False}

        # Generated history uses the attachment identity planner, so a real
        # history.json survives alongside the generated archive across reruns.
        entry.add_attachment(db.add_binary(b"original user file"), "history.json")
        db.save()
        converter = Converter(
            str(path),
            "test",
            None,
            "test",
            None,
            None,
            False,
            0,
            None,
            archive_history=True,
        )
        converter._load_keepass_data()
        key = str(entry.uuid).replace("-", "").upper()
        sources = converter._unpack_entry(converter._entries[key])[3]
        files = [source for source in sources if isinstance(source, SourceFile)]
        assert len(files) == 2
        assert len({source.filename for source in files}) == 2
        original = next(source for source in files if source.kind == "original")
        generated = next(source for source in files if source.kind == "history")
        assert (
            original.filename == "history.json"
            and original.data == b"original user file"
        )
        assert json.loads(generated.data)["entry_uuid"] == str(entry.uuid)
        converter._load_keepass_data()
        assert converter._unpack_entry(converter._entries[key])[3] == sources
        normal = Converter(str(path), "test", None, "test", None, None, False, 0, None)
        normal._load_keepass_data()
        normal_sources = normal._unpack_entry(normal._entries[key])[3]
        assert len(normal_sources) == 1
    print("password history extraction and archive round trips passed")


if __name__ == "__main__":
    main()
