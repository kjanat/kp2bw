import copy
import logging
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import UUID

from lxml.etree import Element
from pykeepass import Attachment, Entry, Group, PyKeePass, create_database

from kp2bw.bw_serve import KP2BW_SYNC_FIELD_NAME, BitwardenServeClient
from kp2bw.bw_types import BwFido2Credential, BwField, BwItemCreate, BwItemResponse
from kp2bw.convert import MAX_BW_ITEM_LENGTH, Converter, EntryValue

REFERENCE_ENTRY_UUID = UUID("12345678-1234-5678-1234-567812345678")
REFERENCE_ENTRY_UUID_REF = REFERENCE_ENTRY_UUID.hex.upper()


class ReferenceEntry(Entry):
    """Minimal Entry double; real Entry init needs a PyKeePass backing store.

    The real ``Entry`` exposes its fields as XML-backed descriptors, so each
    accessed field is overridden here as a plain in-memory property to shadow
    that descriptor and keep the test independent of a ``.kdbx`` store.
    """

    _test_password: str | None
    _test_notes: str | None
    _test_otp: str | None
    _test_expires: bool
    _test_expiry_time: datetime | None
    _test_tags: list[str]
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
        self._test_notes = None
        self._test_otp = None
        self._test_expires = False
        self._test_expiry_time = None
        self._test_tags = []
        self._test_url = url
        self._test_uuid = REFERENCE_ENTRY_UUID
        self._element = Element("Entry")

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

    @property
    def custom_properties(self) -> dict[str, str | None]:
        """Return no extra properties; only ``url`` folds into the referent."""
        return {}

    @property
    def notes(self) -> str | None:
        """Return no notes."""
        return self._test_notes

    @notes.setter
    def notes(self, value: str | None) -> None:
        """Store notes."""
        self._test_notes = value

    @property
    def otp(self) -> str | None:
        """Return no OTP."""
        return self._test_otp

    @otp.setter
    def otp(self, value: str | None) -> None:
        """Store OTP."""
        self._test_otp = value

    @property
    def attachments(self) -> list[Attachment]:
        """Return no attachments."""
        return []

    @property
    def expired(self) -> bool:
        """Return a non-expired state."""
        return False

    @property
    def expires(self) -> bool | None:
        """Return disabled expiry."""
        return self._test_expires

    @expires.setter
    def expires(self, value: bool) -> None:
        """Store expiry enablement."""
        self._test_expires = value

    @property
    def expiry_time(self) -> datetime | None:
        """Return no expiry time."""
        return self._test_expiry_time

    @expiry_time.setter
    def expiry_time(self, value: datetime) -> None:
        """Store expiry time."""
        self._test_expiry_time = value

    @property
    def tags(self) -> list[str]:
        """Return no tags."""
        return self._test_tags

    @tags.setter
    def tags(self, value: list[str] | str) -> None:
        """Store tags."""
        self._test_tags = value if isinstance(value, list) else [value]


class ReferenceResolutionTestConverter(Converter):
    """Converter wired with stubbed lookups to exercise REF resolution alone."""

    duplicate_creates: list[str | None]
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

    def _add_bw_entry_to_entries_dict(self, entry: Entry) -> None:
        """Record each duplicate creation title for diagnostics."""
        self.duplicate_creates.append(entry.title)


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

    def load_and_resolve(
        self,
    ) -> tuple[dict[str, BwItemCreate], dict[str, set[str]]]:
        """Load and resolve, returning items and attachment filenames by name."""
        self._load_keepass_data()
        self._resolve_entries_with_references()
        items = {item["name"]: item for _, _, item, _ in self._entries.values()}
        attachments = {
            item["name"]: {
                self._attachment_filename(attachment)
                for attachment in entry_attachments
            }
            for _, _, item, entry_attachments in self._entries.values()
        }
        return items, attachments

    def legacy_output(self, kp_uuid: str) -> tuple[str, BwItemCreate]:
        """Return the simulated pre-fix REF stamp and item for *kp_uuid*."""
        state = self._legacy_ref_states.get(kp_uuid)
        if state is None:
            raise AssertionError(f"No legacy REF state recorded for {kp_uuid!r}")
        return state.initial_sync_stamp, state.item

    def reconcile_legacy_output(
        self,
        bw: BitwardenServeClient,
        existing: BwItemResponse,
        desired: BwItemCreate,
        *,
        kp_uuid: str,
    ) -> str:
        """Reconcile one simulated pre-fix item and return its outcome."""
        outcome, _, _ = self._reconcile_existing_item(
            bw,
            existing,
            None,
            desired,
            [],
            fixed_coll_id=None,
            kp_uuid=kp_uuid,
        )
        return outcome

    def restamp(self, item: BwItemCreate) -> None:
        """Refresh a desired item's sync stamp for legacy-repair tests."""
        self._stamp_content(item)


class _LegacyUpgradeClient(BitwardenServeClient):
    """Client double recording the safe upgrade PUT for a legacy REF item."""

    updated: list[BwItemResponse]

    def __init__(self) -> None:
        self.updated = []

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        if item_id != "legacy-ref-item":
            raise AssertionError(f"Unexpected update item id: {item_id!r}")
        self.updated.append(item)

    def update_dedup_entry(self, kp_uuid: str, item: BwItemResponse) -> None:
        pass


def _legacy_response(item: BwItemCreate) -> BwItemResponse:
    """Wrap one offline item in the response fields used by reconciliation."""
    return BwItemResponse(
        id="legacy-ref-item",
        object="item",
        revisionDate="2026-01-01T00:00:00Z",
        organizationId=item["organizationId"],
        collectionIds=item["collectionIds"],
        folderId=item["folderId"],
        type=item["type"],
        name=item["name"],
        notes=item["notes"],
        favorite=item["favorite"],
        fields=copy.deepcopy(item["fields"]),
        login=copy.deepcopy(item["login"]),
        secureNote=item["secureNote"],
        card=item["card"],
        identity=item["identity"],
    )


def _run_chain_resolution(
    build: Callable[[PyKeePass, Group], None],
    *,
    include_oversize_secrets: bool = False,
) -> tuple[dict[str, BwItemCreate], dict[str, set[str]], list[str]]:
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

    try:
        with tempfile.TemporaryDirectory(prefix="kp2bw-chain-") as tmp_dir:
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
                include_oversize_secrets=include_oversize_secrets,
            )
            items, attachments = converter.load_and_resolve()
            return items, attachments, capture.messages
    finally:
        convert_logger.removeHandler(capture)
        convert_logger.setLevel(previous_level)


class _OversizeTestConverter(Converter):
    """Converter exposing the offline load with attachments for oversize-field tests."""

    def load_with_attachments(
        self,
    ) -> dict[str, tuple[BwItemCreate, set[str]]]:
        """Load the KeePass DB offline; return each item with its attachment filenames.

        Resolving filenames here (via the inherited ``_attachment_filename``)
        keeps the protected-member access on ``self``, mirroring how the other
        converter test doubles expose internals.
        """
        self._load_keepass_data()
        return {
            item["name"]: (
                item,
                {self._attachment_filename(att) for att in attachments},
            )
            for _, _, item, attachments in self._entries.values()
        }


def _run_oversize(
    build: Callable[[PyKeePass, Group], None],
    *,
    include_oversize_secrets: bool,
) -> tuple[dict[str, tuple[BwItemCreate, set[str]]], list[str]]:
    """Build a temp KeePass DB, run the offline load, return items+attachments+warnings.

    Mirrors :func:`_run_chain_resolution` but exposes attachment filenames and
    the ``include_oversize_secrets`` toggle, and skips REF resolution (not
    needed for these single-entry cases).
    """
    capture = _WarningCapture()
    convert_logger = logging.getLogger("kp2bw.convert")
    previous_level = convert_logger.level
    convert_logger.addHandler(capture)
    convert_logger.setLevel(logging.WARNING)

    try:
        with tempfile.TemporaryDirectory(prefix="kp2bw-oversize-") as tmp_dir:
            db_path = str(Path(tmp_dir) / "oversize.kdbx")
            kp = create_database(db_path, password="pw")
            build(kp, kp.root_group)
            kp.save()

            converter = _OversizeTestConverter(
                keepass_file_path=db_path,
                keepass_password="pw",
                keepass_keyfile_path=None,
                bitwarden_password="pw",
                bitwarden_organization_id=None,
                bitwarden_coll_id=None,
                path2name=False,
                path2nameskip=1,
                import_tags=None,
                include_oversize_secrets=include_oversize_secrets,
            )
            return converter.load_with_attachments(), capture.messages
    finally:
        convert_logger.removeHandler(capture)
        convert_logger.setLevel(previous_level)


def assert_oversize_secret_field_is_not_lost_silently() -> None:
    """An over-limit secret-class field is never silently dropped (#21 follow-up).

    Covers both secret kinds that survive nowhere but a hidden inline field: a
    hidden OTP secret (``HmacOtp-Secret``) and a KeePass-protected custom field.
    Default: each is warned-and-dropped (not written to a plaintext attachment
    without consent) while a non-secret over-limit field is offloaded to its
    ``.txt`` attachment as usual. Opt-in (``--include-oversize-secrets``): each
    secret is offloaded to its attachment too, so no data is lost.
    """
    big = "Z" * (MAX_BW_ITEM_LENGTH + 64)
    secret_keys = ("HmacOtp-Secret", "protected_codes")

    def build(kp: PyKeePass, root: Group) -> None:
        """One entry with two over-limit secret-class fields beside a plain one."""
        entry = kp.add_entry(root, "Big Secret", "user", "pw")
        # HmacOtp-Secret: HOTP cannot migrate to Bitwarden's TOTP, so it would
        # otherwise survive only as a hidden inline field -- over the limit it is
        # dropped entirely, the data-loss edge under test.
        entry.set_custom_property("HmacOtp-Secret", big)
        # A KeePass-protected (Protected="True") field is a secret too, so it
        # must be gated behind the opt-in -- never spilled to a plaintext
        # attachment by default.
        entry.set_custom_property("protected_codes", big, protect=True)
        # Control: a non-secret over-limit field is always offloaded.
        entry.set_custom_property("recovery_codes", big)

    # Default: secrets dropped-with-warning, non-secret still offloaded.
    items, warnings = _run_oversize(build, include_oversize_secrets=False)
    item, att_names = items["Big Secret"]
    if "recovery_codes.txt" not in att_names:
        raise AssertionError("Non-secret over-limit field should always be offloaded")
    for key in secret_keys:
        if f"{key}.txt" in att_names:
            raise AssertionError(f"Secret '{key}' was offloaded without opt-in")
        if any(field["name"] == key for field in item["fields"]):
            raise AssertionError(f"Over-limit secret '{key}' must not be stored inline")
        if not any(key in w and "not migrated" in w for w in warnings):
            raise AssertionError(
                f"Expected a not-migrated warning for dropped '{key}', got {warnings}"
            )

    # Opt-in: each secret is recovered into its attachment, no data lost.
    items, warnings = _run_oversize(build, include_oversize_secrets=True)
    item, att_names = items["Big Secret"]
    for key in secret_keys:
        if f"{key}.txt" not in att_names:
            raise AssertionError(
                f"--include-oversize-secrets should offload secret '{key}'"
            )
        if any(field["name"] == key for field in item["fields"]):
            raise AssertionError(f"Offloaded secret '{key}' must not also be inline")
        if not any(key in w and "offloading" in w for w in warnings):
            raise AssertionError(
                f"Expected an offload warning for '{key}' under opt-in, got {warnings}"
            )


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

    items, _, warnings = _run_chain_resolution(build)

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

    items, _, warnings = _run_chain_resolution(build)

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

    items, _, warnings = _run_chain_resolution(build)

    if "Entry C" not in items:
        raise AssertionError(
            "Normal entry was dropped while handling a reference cycle"
        )
    if {"Entry A", "Entry B"} & set(items):
        raise AssertionError(f"Cyclic entries should not be imported: {sorted(items)}")
    if len(warnings) < 2:
        raise AssertionError(
            "Expected both cyclic entries (A and B) to warn for the unresolvable "
            f"reference cycle, got {warnings}"
        )


def assert_malformed_reference_does_not_abort() -> None:
    """A malformed ``{REF:...}`` token is warned-and-skipped, never fatal.

    A token missing the ``@`` separator made ``_parse_kp_ref_string`` raise an
    uncaught ``ValueError`` that aborted the whole migration; it must now be
    reported and skipped while unrelated entries still import.
    """

    def build(kp: PyKeePass, root: Group) -> None:
        """Add an entry with a malformed REF token plus a normal entry."""
        kp.add_entry(root, "Broken", "userB", "{REF:UI:DEADBEEF}")
        kp.add_entry(root, "Normal", "userN", "passN")

    items, _, warnings = _run_chain_resolution(build)

    if "Normal" not in items:
        raise AssertionError("Normal entry was dropped due to a malformed REF token")
    if "Broken" in items:
        raise AssertionError("Malformed-REF entry should be skipped, not imported")
    if not any("Could not resolve entry for" in w and "Broken" in w for w in warnings):
        raise AssertionError(
            f"Expected a warning for the malformed REF, got: {warnings}"
        )


def _rename_custom_property_key(entry: Entry, old: str, new: str) -> None:
    """Rename a custom key directly so PyKeePass's unsafe setter is not involved."""
    for string_element in entry._element.findall("String"):
        key_element = string_element.find("Key")
        if key_element is not None and key_element.text == old:
            key_element.text = new
            return
    raise AssertionError(f"Custom property {old!r} not found")


def _field(item: BwItemCreate, name: str) -> BwField:
    """Return one named custom field from an offline-converted item."""
    matches = [field for field in item["fields"] if field["name"] == name]
    if len(matches) != 1:
        raise AssertionError(
            f"item {item['name']!r}: expected one field {name!r}, found {len(matches)}"
        )
    return matches[0]


def assert_xpath_like_custom_property_names_are_safe() -> None:
    """Quote-bearing custom keys survive without XPath evaluation or state leaks."""
    dangerous_key = 'quote\'" ] | //String/Value[@Protected="True"]'

    def build(kp: PyKeePass, root: Group) -> None:
        protected = kp.add_entry(root, "Protected", "user-a", "pass-a")
        protected.set_custom_property("placeholder-a", "secret-a", protect=True)
        _rename_custom_property_key(protected, "placeholder-a", dangerous_key)

        plain = kp.add_entry(root, "Plain", "user-b", "pass-b")
        plain.set_custom_property("placeholder-b", "plain-b")
        _rename_custom_property_key(plain, "placeholder-b", dangerous_key)

    items, _, warnings = _run_chain_resolution(build)

    if warnings:
        raise AssertionError(f"Quote-bearing keys logged warnings: {warnings}")
    if _field(items["Protected"], dangerous_key)["type"] != 1:
        raise AssertionError("Protected quote-bearing key was not kept hidden")
    if _field(items["Plain"], dangerous_key)["type"] != 0:
        raise AssertionError("Protection state leaked between adjacent entries")


def assert_distinct_ref_preserves_protected_properties() -> None:
    """A REF that becomes its own item retains hidden-field protection."""

    def build(kp: PyKeePass, root: Group) -> None:
        target = kp.add_entry(root, "Target", "target-user", "shared-password")
        alias = kp.add_entry(
            root,
            "Distinct REF",
            "different-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
        )
        alias.set_custom_property("private-code", "sensitive", protect=True)

    items, _, warnings = _run_chain_resolution(build)

    if set(items) != {"Target", "Distinct REF"}:
        raise AssertionError(f"Distinct REF item missing: {sorted(items)}")
    if _field(items["Distinct REF"], "private-code")["type"] != 1:
        raise AssertionError("Distinct REF protected field became visible text")
    if warnings:
        raise AssertionError(f"Distinct REF unexpectedly logged warnings: {warnings}")


def assert_distinct_ref_protects_oversize_secrets() -> None:
    """REF-created items obey the opt-in gate for oversized protected values."""
    large_secret = "S" * (MAX_BW_ITEM_LENGTH + 1)

    def build(kp: PyKeePass, root: Group) -> None:
        target = kp.add_entry(root, "Target", "target-user", "shared-password")
        alias = kp.add_entry(
            root,
            "Large REF Secret",
            "different-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
        )
        alias.set_custom_property("recovery-secret", large_secret, protect=True)

    items, attachments, warnings = _run_chain_resolution(
        build, include_oversize_secrets=False
    )
    if "recovery-secret.txt" in attachments["Large REF Secret"]:
        raise AssertionError("REF protected value was offloaded without opt-in")
    if any(
        field["name"] == "recovery-secret"
        for field in items["Large REF Secret"]["fields"]
    ):
        raise AssertionError("Oversized REF protected value was stored inline")
    if not any(
        "recovery-secret" in warning and "not migrated" in warning
        for warning in warnings
    ):
        raise AssertionError("Missing warning for dropped oversized REF secret")

    _, attachments, warnings = _run_chain_resolution(
        build, include_oversize_secrets=True
    )
    if "recovery-secret.txt" not in attachments["Large REF Secret"]:
        raise AssertionError("REF protected value was not offloaded with opt-in")
    if not any(
        "recovery-secret" in warning and "offloading" in warning for warning in warnings
    ):
        raise AssertionError("Missing warning for opt-in REF secret offload")


def assert_matching_ref_merges_totp_and_restamps() -> None:
    """A matching REF contributes normalized TOTP and leaves a valid sync stamp."""

    def build(kp: PyKeePass, root: Group) -> None:
        target = kp.add_entry(
            root,
            "TOTP Target",
            "shared-user",
            "shared-password",
            url="https://target.example",
        )
        alias = kp.add_entry(
            root,
            "TOTP Alias",
            "shared-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
            url="https://alias.example",
        )
        alias.set_custom_property(
            "TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930"
        )
        alias.set_custom_property("TimeOtp-Algorithm", "HMAC-SHA-256")
        alias.set_custom_property("TimeOtp-Length", "8")
        alias.set_custom_property("TimeOtp-Period", "45")

    items, _, warnings = _run_chain_resolution(build)

    if warnings:
        raise AssertionError(f"Compatible REF TOTP logged warnings: {warnings}")
    if set(items) != {"TOTP Target"}:
        raise AssertionError(f"Matching REF should merge, got {sorted(items)}")

    target = items["TOTP Target"]
    totp = target["login"]["totp"] or ""
    if not totp.startswith("otpauth://totp/"):
        raise AssertionError("REF TOTP was not normalized to an otpauth URI")
    if not all(
        token in totp for token in ("algorithm=SHA256", "digits=8", "period=45")
    ):
        raise AssertionError("REF TOTP lost non-default configuration")
    if any(field["name"].startswith("TimeOtp-") for field in target["fields"]):
        raise AssertionError("Consumed REF TOTP fields leaked into custom fields")
    if _field(target, KP2BW_SYNC_FIELD_NAME)["value"] != Converter._content_signature(
        target
    ):
        raise AssertionError("REF merge left a stale KP2BW_SYNC stamp")


def assert_matching_ref_accepts_semantically_equal_totp() -> None:
    """Equivalent TOTP settings merge even when generated URI labels differ."""

    def add_totp(entry: Entry) -> None:
        entry.set_custom_property(
            "TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930"
        )
        entry.set_custom_property("TimeOtp-Algorithm", "HMAC-SHA-256")
        entry.set_custom_property("TimeOtp-Length", "8")

    def build(kp: PyKeePass, root: Group) -> None:
        target = kp.add_entry(
            root, "Equivalent Target", "shared-user", "shared-password"
        )
        add_totp(target)
        alias = kp.add_entry(
            root,
            "Different Label",
            "shared-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
            url="https://equivalent.example",
        )
        add_totp(alias)

    items, _, warnings = _run_chain_resolution(build)

    if warnings:
        raise AssertionError(f"Equivalent REF TOTP logged warnings: {warnings}")
    if set(items) != {"Equivalent Target"}:
        raise AssertionError(f"Equivalent TOTP split the REF: {sorted(items)}")
    uri_values = {uri["uri"] for uri in items["Equivalent Target"]["login"]["uris"]}
    if "https://equivalent.example" not in uri_values:
        raise AssertionError("Equivalent-TOTP REF did not merge its URL")


def assert_strict_signature_ignores_fido_key_order() -> None:
    """Equivalent FIDO dictionaries retain one strict legacy signature."""
    credential = BwFido2Credential(
        credentialId="credential-id",
        keyType="public-key",
        keyAlgorithm="ECDSA",
        keyCurve="P-256",
        keyValue="key-value",
        rpId="example.com",
        rpName="Example",
        userHandle="user-handle",
        userName="user",
        userDisplayName="User",
        counter="0",
        discoverable="true",
        creationDate=None,
    )
    reordered = BwFido2Credential(
        creationDate=credential["creationDate"],
        discoverable=credential["discoverable"],
        counter=credential["counter"],
        userDisplayName=credential["userDisplayName"],
        userName=credential["userName"],
        userHandle=credential["userHandle"],
        rpName=credential["rpName"],
        rpId=credential["rpId"],
        keyValue=credential["keyValue"],
        keyCurve=credential["keyCurve"],
        keyAlgorithm=credential["keyAlgorithm"],
        keyType=credential["keyType"],
        credentialId=credential["credentialId"],
    )
    first_login = _make_referenced_item()["login"]
    first_login["fido2Credentials"] = [credential]
    reordered_login = copy.deepcopy(first_login)
    reordered_login["fido2Credentials"] = [reordered]

    if Converter._strict_login_signature(
        first_login
    ) != Converter._strict_login_signature(reordered_login):
        raise AssertionError("FIDO dictionary order changed the legacy signature")


def assert_pre_fix_ref_output_upgrades_without_force() -> None:
    """Exact old URI-only output gains REF TOTP despite its known-stale stamp."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-ref-upgrade-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "upgrade.kdbx")
        kp = create_database(db_path, password="pw")
        target = kp.add_entry(
            kp.root_group,
            "Upgrade Target",
            "shared-user",
            "shared-password",
            url="https://upgrade-target.example",
        )
        alias = kp.add_entry(
            kp.root_group,
            "Upgrade Alias",
            "shared-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
            url="https://upgrade-alias.example",
        )
        alias.set_custom_property("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")
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
        items, _ = converter.load_and_resolve()

    desired = items["Upgrade Target"]
    kp_uuid = _field(desired, "KP2BW_ID")["value"]
    initial_stamp, legacy_item = converter.legacy_output(kp_uuid)
    if legacy_item["login"]["totp"] is not None:
        raise AssertionError("Simulated pre-fix REF output unexpectedly contains TOTP")
    if _field(legacy_item, KP2BW_SYNC_FIELD_NAME)["value"] != initial_stamp:
        raise AssertionError("Simulated pre-fix REF output lost its stale stamp")

    existing = _legacy_response(legacy_item)
    existing_login = existing.get("login")
    if existing_login is None:
        raise AssertionError("Legacy REF fixture has no login")
    existing_login["passwordRevisionDate"] = "2026-01-01T00:00:00Z"

    manually_edited = copy.deepcopy(existing)
    edited_login = manually_edited.get("login")
    if edited_login is None:
        raise AssertionError("Legacy REF fixture has no login")
    edited_login["uris"][0]["match"] = 3
    edited_bw = _LegacyUpgradeClient()
    edited_outcome = converter.reconcile_legacy_output(
        edited_bw, manually_edited, desired, kp_uuid=kp_uuid
    )
    if edited_outcome != "protected" or edited_bw.updated:
        raise AssertionError("Legacy recognition overwrote a manual URI-match edit")

    removed_uri = copy.deepcopy(existing)
    removed_login = removed_uri.get("login")
    if removed_login is None:
        raise AssertionError("Legacy REF fixture has no login")
    removed_login["uris"] = [
        uri
        for uri in removed_login["uris"]
        if uri["uri"] != "https://upgrade-alias.example"
    ]
    removed_bw = _LegacyUpgradeClient()
    removed_outcome = converter.reconcile_legacy_output(
        removed_bw, removed_uri, desired, kp_uuid=kp_uuid
    )
    if removed_outcome != "protected" or removed_bw.updated:
        raise AssertionError("Legacy recognition restored a manually removed URI")

    bw = _LegacyUpgradeClient()
    outcome = converter.reconcile_legacy_output(bw, existing, desired, kp_uuid=kp_uuid)

    if outcome != "updated" or len(bw.updated) != 1:
        raise AssertionError("Exact pre-fix REF output was not upgraded with one PUT")
    updated_login = bw.updated[0].get("login")
    if updated_login is None or updated_login["totp"] is None:
        raise AssertionError("Pre-fix REF upgrade did not add the alias TOTP")
    if updated_login["passwordRevisionDate"] != "2026-01-01T00:00:00Z":
        raise AssertionError("Pre-fix REF upgrade cleared password revision metadata")

    stamp_only_desired = copy.deepcopy(legacy_item)
    converter.restamp(stamp_only_desired)
    stamp_only_existing = copy.deepcopy(existing)
    stamp_only_login = stamp_only_existing.get("login")
    if stamp_only_login is None:
        raise AssertionError("Legacy stamp-only fixture has no login")
    stamp_bw = _LegacyUpgradeClient()
    stamp_outcome = converter.reconcile_legacy_output(
        stamp_bw, stamp_only_existing, stamp_only_desired, kp_uuid=kp_uuid
    )
    if stamp_outcome != "updated" or len(stamp_bw.updated) != 1:
        raise AssertionError("Exact legacy REF stamp was not repaired")
    repaired_login = stamp_bw.updated[0].get("login")
    if (
        repaired_login is None
        or repaired_login["passwordRevisionDate"] != "2026-01-01T00:00:00Z"
    ):
        raise AssertionError("Stamp-only repair rewrote unchanged login metadata")


def assert_conflicting_ref_totp_creates_separate_item() -> None:
    """Different non-empty TOTPs are preserved on separate items, never overwritten."""
    target_secret = "JBSWY3DPEHPK3PXP"
    alias_secret = "GEZDGNBVGY3TQOJQ"

    def build(kp: PyKeePass, root: Group) -> None:
        target = kp.add_entry(root, "Conflict Target", "shared-user", "shared-password")
        target.set_custom_property("TimeOtp-Secret-Base32", target_secret)
        alias = kp.add_entry(
            root,
            "Conflict Alias",
            "shared-user",
            f"{{REF:P@I:{target.uuid.hex.upper()}}}",
        )
        alias.set_custom_property("TimeOtp-Secret-Base32", alias_secret)

    items, _, warnings = _run_chain_resolution(build)

    if set(items) != {"Conflict Target", "Conflict Alias"}:
        raise AssertionError(f"Conflicting TOTP item was lost: {sorted(items)}")
    if items["Conflict Target"]["login"]["totp"] != target_secret:
        raise AssertionError("Referent TOTP changed during conflict handling")
    if items["Conflict Alias"]["login"]["totp"] != alias_secret:
        raise AssertionError("REF alias TOTP was not preserved")
    if not any("TOTP" in warning and "conflicts" in warning for warning in warnings):
        raise AssertionError("Conflicting REF TOTP did not emit a warning")
    if any(
        secret in warning
        for secret in (target_secret, alias_secret)
        for warning in warnings
    ):
        raise AssertionError("REF TOTP conflict warning exposed a secret")


def assert_conflicting_ref_totp_is_order_independent() -> None:
    """Stable UUID order decides conflicting sibling aliases, not XML order."""
    target_uuid = UUID("30000000-0000-0000-0000-000000000000")
    first_uuid = UUID("10000000-0000-0000-0000-000000000000")
    second_uuid = UUID("20000000-0000-0000-0000-000000000000")
    first_secret = "JBSWY3DPEHPK3PXP"
    second_secret = "GEZDGNBVGY3TQOJQ"

    def run(*, reverse: bool) -> tuple[dict[str, BwItemCreate], list[str]]:
        def build(kp: PyKeePass, root: Group) -> None:
            target = kp.add_entry(
                root, "Order Target", "shared-user", "shared-password"
            )
            target.uuid = target_uuid
            aliases = [
                ("First Alias", first_uuid, first_secret, "https://first.example"),
                (
                    "Second Alias",
                    second_uuid,
                    second_secret,
                    "https://second.example",
                ),
            ]
            for title, entry_uuid, secret, url in aliases[:: -1 if reverse else 1]:
                alias = kp.add_entry(
                    root,
                    title,
                    "shared-user",
                    f"{{REF:P@I:{target_uuid.hex.upper()}}}",
                    url=url,
                )
                alias.uuid = entry_uuid
                alias.set_custom_property("TimeOtp-Secret-Base32", secret)

        items, _, warnings = _run_chain_resolution(build)
        return items, warnings

    forward_items, forward_warnings = run(reverse=False)
    reverse_items, reverse_warnings = run(reverse=True)

    if forward_items != reverse_items or forward_warnings != reverse_warnings:
        raise AssertionError("Conflicting sibling REF output depends on XML order")
    if set(forward_items) != {"Order Target", "Second Alias"}:
        raise AssertionError("Stable REF conflict winner was not selected by UUID")
    if forward_items["Order Target"]["login"]["totp"] != first_secret:
        raise AssertionError("Lower-UUID REF TOTP did not merge deterministically")
    if forward_items["Second Alias"]["login"]["totp"] != second_secret:
        raise AssertionError("Conflicting sibling REF TOTP was not preserved")


def assert_legacy_ref_shadow_preserves_historical_order() -> None:
    """Legacy recognition replays XML order while fresh output uses UUID order."""
    target_uuid = UUID("30000000-0000-0000-0000-000000000000")
    lower_uuid = UUID("10000000-0000-0000-0000-000000000000")
    higher_uuid = UUID("20000000-0000-0000-0000-000000000000")

    with tempfile.TemporaryDirectory(prefix="kp2bw-ref-order-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "legacy-order.kdbx")
        kp = create_database(db_path, password="pw")
        target = kp.add_entry(
            kp.root_group,
            "Legacy Order Target",
            "shared-user",
            "shared-password",
            url="https://target.example",
        )
        target.uuid = target_uuid

        xml_first = kp.add_entry(
            kp.root_group,
            "Higher UUID Alias",
            "shared-user",
            f"{{REF:P@I:{target_uuid.hex.upper()}}}",
            url="https://higher.example",
        )
        xml_first.uuid = higher_uuid
        xml_second = kp.add_entry(
            kp.root_group,
            "Lower UUID Alias",
            "shared-user",
            f"{{REF:P@I:{target_uuid.hex.upper()}}}",
            url="https://lower.example",
        )
        xml_second.uuid = lower_uuid
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
        items, _ = converter.load_and_resolve()

    desired = items["Legacy Order Target"]
    kp_uuid = _field(desired, "KP2BW_ID")["value"]
    _, legacy_item = converter.legacy_output(kp_uuid)
    legacy_uris = [uri["uri"] for uri in legacy_item["login"]["uris"]]
    if legacy_uris != [
        "https://target.example",
        "https://higher.example",
        "https://lower.example",
    ]:
        raise AssertionError("Legacy REF shadow did not preserve XML traversal order")

    desired_uris = [uri["uri"] for uri in desired["login"]["uris"]]
    if desired_uris != [
        "https://target.example",
        "https://lower.example",
        "https://higher.example",
    ]:
        raise AssertionError("Fresh REF output did not use stable UUID order")

    bw = _LegacyUpgradeClient()
    outcome = converter.reconcile_legacy_output(
        bw, _legacy_response(legacy_item), desired, kp_uuid=kp_uuid
    )
    if outcome != "updated" or len(bw.updated) != 1:
        raise AssertionError("Historical REF URI order was not recognized safely")


def assert_legacy_ref_chain_preserves_historical_destination() -> None:
    """A newly split middle REF still replays its parent's old root merge."""
    root_uuid = UUID("30000000-0000-0000-0000-000000000000")
    middle_uuid = UUID("10000000-0000-0000-0000-000000000000")
    leaf_uuid = UUID("20000000-0000-0000-0000-000000000000")

    with tempfile.TemporaryDirectory(prefix="kp2bw-ref-chain-upgrade-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "legacy-chain.kdbx")
        kp = create_database(db_path, password="pw")
        root = kp.add_entry(
            kp.root_group,
            "Legacy Chain Root",
            "shared-user",
            "shared-password",
            url="https://root.example",
        )
        root.uuid = root_uuid
        root.set_custom_property("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")

        middle = kp.add_entry(
            kp.root_group,
            "Legacy Chain Middle",
            "shared-user",
            f"{{REF:P@I:{root_uuid.hex.upper()}}}",
            url="https://middle.example",
        )
        middle.uuid = middle_uuid
        middle.set_custom_property("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ")

        leaf = kp.add_entry(
            kp.root_group,
            "Legacy Chain Leaf",
            "shared-user",
            f"{{REF:P@I:{middle_uuid.hex.upper()}}}",
            url="https://leaf.example",
        )
        leaf.uuid = leaf_uuid
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
        items, _ = converter.load_and_resolve()

    if set(items) != {"Legacy Chain Root", "Legacy Chain Middle"}:
        raise AssertionError("Conflicting middle REF did not split losslessly")
    middle_uris = [uri["uri"] for uri in items["Legacy Chain Middle"]["login"]["uris"]]
    if middle_uris != ["https://middle.example", "https://leaf.example"]:
        raise AssertionError("Leaf REF did not merge into the new middle item")

    desired_root = items["Legacy Chain Root"]
    kp_uuid = _field(desired_root, "KP2BW_ID")["value"]
    _, legacy_root = converter.legacy_output(kp_uuid)
    legacy_uris = [uri["uri"] for uri in legacy_root["login"]["uris"]]
    if legacy_uris != [
        "https://root.example",
        "https://middle.example",
        "https://leaf.example",
    ]:
        raise AssertionError("Legacy REF chain replay changed canonical destination")

    bw = _LegacyUpgradeClient()
    outcome = converter.reconcile_legacy_output(
        bw, _legacy_response(legacy_root), desired_root, kp_uuid=kp_uuid
    )
    if outcome != "updated" or len(bw.updated) != 1:
        raise AssertionError("Historical REF chain output was not recognized safely")


def assert_refs_to_different_items_do_not_merge_arbitrarily() -> None:
    """Username/password references to different items produce a distinct alias."""

    def build(kp: PyKeePass, root: Group) -> None:
        username_source = kp.add_entry(
            root, "Username Source", "shared-user", "shared-password"
        )
        password_source = kp.add_entry(
            root, "Password Source", "shared-user", "shared-password"
        )
        kp.add_entry(
            root,
            "Mixed REF",
            f"{{REF:U@I:{username_source.uuid.hex.upper()}}}",
            f"{{REF:P@I:{password_source.uuid.hex.upper()}}}",
        )

    items, _, warnings = _run_chain_resolution(build)

    if set(items) != {"Username Source", "Password Source", "Mixed REF"}:
        raise AssertionError(f"Mixed REF was merged arbitrarily: {sorted(items)}")
    if not any("different entries" in warning for warning in warnings):
        raise AssertionError("Mixed REF did not explain why it stayed separate")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_resolves_none_fields_with_references()
    assert_resolves_chain_with_merge()
    assert_resolves_chain_into_distinct_items()
    assert_reference_cycle_terminates()
    assert_malformed_reference_does_not_abort()
    assert_oversize_secret_field_is_not_lost_silently()
    assert_xpath_like_custom_property_names_are_safe()
    assert_distinct_ref_preserves_protected_properties()
    assert_distinct_ref_protects_oversize_secrets()
    assert_matching_ref_merges_totp_and_restamps()
    assert_matching_ref_accepts_semantically_equal_totp()
    assert_strict_signature_ignores_fido_key_order()
    assert_pre_fix_ref_output_upgrades_without_force()
    assert_conflicting_ref_totp_creates_separate_item()
    assert_conflicting_ref_totp_is_order_independent()
    assert_legacy_ref_shadow_preserves_historical_order()
    assert_legacy_ref_chain_preserves_historical_destination()
    assert_refs_to_different_items_do_not_merge_arbitrarily()
    print("convert reference resolution test passed")


if __name__ == "__main__":
    main()
