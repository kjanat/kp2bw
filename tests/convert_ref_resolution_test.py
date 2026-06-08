from uuid import UUID

from pykeepass import Entry, Group

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


def main() -> None:
    """Run the script-style assertion and report success."""
    assert_resolves_none_fields_with_references()
    print("convert reference resolution test passed")


if __name__ == "__main__":
    main()
