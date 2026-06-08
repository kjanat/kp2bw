import logging
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from pykeepass import Entry, Group, PyKeePass, create_database

from kp2bw.bw_types import BwItemCreate
from kp2bw.convert import Converter, EntryValue

REFERENCE_ENTRY_UUID = UUID("12345678-1234-5678-1234-567812345678")
REFERENCE_ENTRY_UUID_REF = REFERENCE_ENTRY_UUID.hex.upper()


class ReferenceEntry(Entry):
    """Minimal Entry double; real Entry init needs a PyKeePass backing store.

    The real ``Entry`` exposes its fields as XML-backed descriptors, so each
    accessed field is overridden here as a plain in-memory property to shadow
    that descriptor and keep the test independent of a ``.kdbx`` store.
    """

    _test_password: str | None
    _test_title: str | None
    _test_url: str | None
    _test_username: str | None
    _test_uuid: UUID

    def __init__(
        self,
        *,
        title: str | None,
        username: str | None,
        password: str | None,
        url: str | None,
    ) -> None:
        """Seed the in-memory field backing store without touching PyKeePass."""
        self._test_title = title
        self._test_username = username
        self._test_password = password
        self._test_url = url
        self._test_uuid = REFERENCE_ENTRY_UUID

    @property
    def title(self) -> str | None:
        """Return the entry title."""
        return self._test_title

    @title.setter
    def title(self, value: str | None) -> None:
        """Store the entry title."""
        self._test_title = value

    @property
    def username(self) -> str | None:
        """Return the username (may be ``None``, the case under test)."""
        return self._test_username

    @username.setter
    def username(self, value: str | None) -> None:
        """Store the username, as REF resolution does via ``setattr``."""
        self._test_username = value

    @property
    def password(self) -> str | None:
        """Return the password (may be ``None`` or a ``{REF:...}`` string)."""
        return self._test_password

    @password.setter
    def password(self, value: str | None) -> None:
        """Store the password, as REF resolution does via ``setattr``."""
        self._test_password = value

    @property
    def url(self) -> str | None:
        """Return the URL merged onto the referenced item as a URI."""
        return self._test_url

    @url.setter
    def url(self, value: str | None) -> None:
        """Store the URL."""
        self._test_url = value

    @property
    def uuid(self) -> UUID:
        """Return the fixed entry UUID used for warning messages."""
        return self._test_uuid

    @uuid.setter
    def uuid(self, uuid: UUID) -> None:
        """Store the entry UUID."""
        self._test_uuid = uuid

    @property
    def group(self) -> Group | None:
        """Return ``None``; the double is not attached to any group."""
        return None


class ReferenceResolutionTestConverter(Converter):
    """Converter wired with stubbed lookups to exercise REF resolution alone."""

    duplicate_creates: list[tuple[str | None, list[str] | None]]
    referenced_item: BwItemCreate

    def __init__(self, referenced_item: BwItemCreate) -> None:
        """Build a converter against dummy credentials and a fixed referent."""
        super().__init__(
            keepass_file_path="dummy.kdbx",
            keepass_password="password",
            keepass_keyfile_path=None,
            bitwarden_password="password",
            bitwarden_organization_id=None,
            bitwarden_coll_id=None,
            path2name=False,
            path2nameskip=1,
            import_tags=None,
        )
        self.duplicate_creates = []
        self.referenced_item = referenced_item

    def add_ref_entry(self, entry: Entry) -> None:
        """Register *entry* as the sole REF entry to resolve."""
        self._kp_ref_entries = [entry]

    def resolve_references(self) -> None:
        """Run the method under test."""
        self._resolve_entries_with_references()

    def _get_referenced_entry(
        self, lookup_mode: str, ref_compare_string: str
    ) -> EntryValue:
        """Return the fixed referent, asserting the REF was parsed and dispatched."""
        if lookup_mode != "I":
            raise AssertionError(f"Unexpected REF lookup_mode: {lookup_mode}")
        if ref_compare_string != REFERENCE_ENTRY_UUID_REF:
            raise AssertionError(f"Unexpected REF target: {ref_compare_string}")
        return (None, None, self.referenced_item, [])

    def _find_referenced_value(
        self, ref_entry: BwItemCreate, field_referenced: str
    ) -> str | None:
        """Resolve a ``P`` (password) reference; reject anything else."""
        if field_referenced == "P":
            return ref_entry["login"]["password"]
        raise AssertionError(f"Unexpected REF field: {field_referenced}")

    def _add_bw_entry_to_entries_dict(
        self, entry: Entry, custom_protected: list[str] | None
    ) -> None:
        """Record each duplicate creation (title, protected) for diagnostics."""
        self.duplicate_creates.append((entry.title, custom_protected))


def _make_referenced_item() -> BwItemCreate:
    """Build a Bitwarden item whose creds match the resolved REF entry."""
    return {
        "organizationId": None,
        "collectionIds": [],
        "folderId": None,
        "type": 1,
        "name": "Referenced Entry",
        "notes": None,
        "favorite": False,
        "fields": [],
        "login": {
            "uris": [],
            "username": "",
            "password": "resolved_value",
            "totp": None,
            "passwordRevisionDate": None,
        },
        "secureNote": None,
        "card": None,
        "identity": None,
    }


def assert_resolves_none_fields_with_references() -> None:
    """Assert a REF entry with a ``None`` username resolves and merges its URI."""
    referenced_item = _make_referenced_item()
    converter = ReferenceResolutionTestConverter(referenced_item)

    entry = ReferenceEntry(
        title="Test Entry",
        username=None,
        password=f"{{REF:P@I:{REFERENCE_ENTRY_UUID_REF}}}",
        url="https://example.com",
    )

    try:
        converter.add_ref_entry(entry)
        converter.resolve_references()
    except TypeError as e:
        raise AssertionError(f"Failed to resolve entries with None fields: {e}") from e
    except Exception as e:
        raise AssertionError(
            f"Caught unexpected exception: {type(e).__name__}: {e}"
        ) from e

    if entry.password != "resolved_value":
        raise AssertionError("REF password was not resolved to referenced value")

    if converter.duplicate_creates:
        raise AssertionError(
            f"Resolved REF entry should merge URI, not create duplicate: "
            f"{converter.duplicate_creates}"
        )

    uris = referenced_item["login"]["uris"]
    if len(uris) != 1 or uris[0]["uri"] != "https://example.com":
        raise AssertionError(
            "Resolved REF entry URI was not appended to referenced item"
        )


class _WarningCapture(logging.Handler):
    """Log handler that records ``WARNING``+ messages for assertions."""

    messages: list[str]

    def __init__(self) -> None:
        """Initialise with an empty message buffer."""
        super().__init__()
        self.messages = []

    def emit(self, record: logging.LogRecord) -> None:
        """Record the formatted message when at ``WARNING`` level or above."""
        if record.levelno >= logging.WARNING:
            self.messages.append(record.getMessage())


class ChainResolutionTestConverter(Converter):
    """Converter exposing the offline pipeline stages for white-box chain tests."""

    def load_and_resolve(self) -> dict[str, BwItemCreate]:
        """Load the KeePass DB, resolve references, return surviving items by name."""
        self._load_keepass_data()
        self._resolve_entries_with_references()
        return {item["name"]: item for _, _, item, _ in self._entries.values()}


def _run_chain_resolution(
    build: Callable[[PyKeePass, Group], None],
) -> tuple[dict[str, BwItemCreate], list[str]]:
    """Build a temp KeePass DB, run load + REF resolution, return items + warnings.

    *build* receives the open database and its root group and populates them
    with entries (typically a chain of ``{REF:...}`` references). The converter
    is driven through the offline part of the pipeline only -- loading and
    reference resolution -- so no Bitwarden connection is needed. Returns the
    surviving items keyed by name plus any warnings the converter logged.
    """
    capture = _WarningCapture()
    convert_logger = logging.getLogger("kp2bw.convert")
    previous_level = convert_logger.level
    convert_logger.addHandler(capture)
    convert_logger.setLevel(logging.WARNING)

    tmp_dir = tempfile.mkdtemp(prefix="kp2bw-chain-")
    try:
        db_path = str(Path(tmp_dir) / "chain.kdbx")
        kp = create_database(db_path, password="pw")
        build(kp, kp.root_group)
        kp.save()

        converter = ChainResolutionTestConverter(
            keepass_file_path=db_path,
            keepass_password="pw",
            keepass_keyfile_path=None,
            bitwarden_password="pw",
            bitwarden_organization_id=None,
            bitwarden_coll_id=None,
            path2name=False,
            path2nameskip=1,
            import_tags=None,
        )
        return converter.load_and_resolve(), capture.messages
    finally:
        convert_logger.removeHandler(capture)
        convert_logger.setLevel(previous_level)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def assert_resolves_chain_with_merge() -> None:
    """``A -> B -> C`` with identical creds merges every URL onto one item.

    Regression for the chained-reference ``KeyError``: ``B`` consolidates into
    ``C`` (matching creds) and so is absent from the entries dict; ``A``'s
    reference to ``B`` must still resolve through the chain instead of raising
    ``KeyError`` and silently dropping ``A``.
    """

    def build(kp: PyKeePass, root: Group) -> None:
        """Populate the DB with a fully credential-matching reference chain."""
        entry_c = kp.add_entry(
            root, "Entry C", "shared", "secret", url="https://c.example"
        )
        c_ref = entry_c.uuid.hex.upper()
        entry_b = kp.add_entry(
            root, "Entry B", "shared", f"{{REF:P@I:{c_ref}}}", url="https://b.example"
        )
        b_ref = entry_b.uuid.hex.upper()
        kp.add_entry(
            root, "Entry A", "shared", f"{{REF:P@I:{b_ref}}}", url="https://a.example"
        )

    items, warnings = _run_chain_resolution(build)

    if warnings:
        raise AssertionError(f"Chain resolution logged warnings: {warnings}")
    if set(items) != {"Entry C"}:
        raise AssertionError(
            f"Chain entries should merge into the single referent, got {sorted(items)}"
        )
    uris = sorted(uri["uri"] for uri in items["Entry C"]["login"]["uris"])
    if uris != ["https://a.example", "https://b.example", "https://c.example"]:
        raise AssertionError(
            f"Chain URLs were not all merged onto the referent: {uris}"
        )


def assert_resolves_chain_into_distinct_items() -> None:
    """``A -> B -> C -> D`` with distinct usernames resolves each password to D's.

    Every link has a different username, so each becomes its own item; the
    password reference must still follow the chain all the way down to ``D``.
    """

    def build(kp: PyKeePass, root: Group) -> None:
        """Populate the DB with a four-deep chain of distinct entries."""
        entry_d = kp.add_entry(
            root, "Entry D", "userD", "passD", url="https://d.example"
        )
        d_ref = entry_d.uuid.hex.upper()
        entry_c = kp.add_entry(
            root, "Entry C", "userC", f"{{REF:P@I:{d_ref}}}", url="https://c.example"
        )
        c_ref = entry_c.uuid.hex.upper()
        entry_b = kp.add_entry(
            root, "Entry B", "userB", f"{{REF:P@I:{c_ref}}}", url="https://b.example"
        )
        b_ref = entry_b.uuid.hex.upper()
        kp.add_entry(
            root, "Entry A", "userA", f"{{REF:P@I:{b_ref}}}", url="https://a.example"
        )

    items, warnings = _run_chain_resolution(build)

    if warnings:
        raise AssertionError(f"Chain resolution logged warnings: {warnings}")
    if set(items) != {"Entry A", "Entry B", "Entry C", "Entry D"}:
        raise AssertionError(f"Expected all four entries imported, got {sorted(items)}")
    for name in ("Entry A", "Entry B", "Entry C"):
        password = items[name]["login"]["password"]
        if password != "passD":
            raise AssertionError(
                f"{name} password resolved to {password!r}, expected 'passD'"
            )


def assert_reference_cycle_terminates() -> None:
    """A ``A <-> B`` reference cycle terminates without dropping unrelated items.

    The cycle cannot be resolved, so both entries warn and are skipped, but the
    resolver must not recurse forever and the normal entry ``C`` must survive.
    """

    def build(kp: PyKeePass, root: Group) -> None:
        """Populate the DB with a two-entry reference cycle plus a normal entry."""
        entry_a = kp.add_entry(root, "Entry A", "userA", "placeholder")
        entry_b = kp.add_entry(root, "Entry B", "userB", "placeholder")
        entry_a.password = f"{{REF:P@I:{entry_b.uuid.hex.upper()}}}"
        entry_b.password = f"{{REF:P@I:{entry_a.uuid.hex.upper()}}}"
        kp.add_entry(root, "Entry C", "userC", "passC")

    items, warnings = _run_chain_resolution(build)

    if "Entry C" not in items:
        raise AssertionError(
            "Normal entry was dropped while handling a reference cycle"
        )
    if {"Entry A", "Entry B"} & set(items):
        raise AssertionError(f"Cyclic entries should not be imported: {sorted(items)}")
    if not warnings:
        raise AssertionError("Expected a warning for the unresolvable reference cycle")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_resolves_none_fields_with_references()
    assert_resolves_chain_with_merge()
    assert_resolves_chain_into_distinct_items()
    assert_reference_cycle_terminates()
    print("convert reference resolution test passed")


if __name__ == "__main__":
    main()
