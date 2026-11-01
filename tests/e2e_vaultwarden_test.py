import difflib
import hashlib
import logging
import struct
import sys
import zlib
from collections.abc import Callable
from pathlib import Path

from e2e_attachment_batch_test import run_attachment_batch_test
from e2e_attachment_identity_test import (
    run_attachment_added_test,
    run_attachment_identity_test,
    run_attachment_legacy_test,
    run_attachment_rejected_test,
)
from e2e_checkpoint_test import CRASH_MODES, crash_check, run_checkpoint_test
from e2e_field_limits_test import run_field_limits_org_test, run_field_limits_test
from e2e_fixups_test import (
    run_fixups_personal_test,
    run_fixups_test,
    run_fixups_uri_only_test,
)
from e2e_history_archive_test import (
    run_history_archive_cli_test,
    run_history_archive_test,
    run_history_updates_test,
)
from e2e_item_selection_test import (
    run_item_selection_force_test,
    run_item_selection_rejected_test,
    run_item_selection_test,
)
from e2e_metadata_test import run_metadata_legacy_ref_test, run_metadata_test
from e2e_passkey_test import run_passkey_test
from e2e_preview_test import (
    run_preview_protected_test,
    run_preview_resume_converge_test,
    run_preview_resume_test,
    run_preview_test,
    run_preview_update_test,
)
from e2e_reserved_fields_test import run_reserved_fields_test
from e2e_scope_test import (
    run_scope_migrate_uris_test,
    run_scope_report_test,
    run_scope_strip_test,
    run_scope_test,
)
from e2e_ssh_test import (
    run_ssh_cli_test,
    run_ssh_protected_test,
    run_ssh_rotation_test,
    run_ssh_test,
)
from e2e_support import Vault, vault_main
from e2e_templates_test import (
    run_templates_cli_test,
    run_templates_selected_test,
    run_templates_test,
)
from pykeepass import PyKeePass, create_database
from snapshot import (
    JsonValue,
    NormField,
    NormItem,
    NormLogin,
    NormVault,
    assert_matches_golden,
    attachment_key,
    canonical_json,
    env_flag,
    normalize_vault,
    objects,
    opt_str,
)

from kp2bw.bw_types import BwItemResponse
from kp2bw.convert import Converter
from kp2bw.uri_mapping import is_url_attribute_key

logger = logging.getLogger("e2e")

SNAPSHOT_DIR = Path(__file__).resolve().parent / "__snapshots__"
GOLDEN_INITIAL = SNAPSHOT_DIR / "vault_initial.json"
GOLDEN_AFTER_UPDATE = SNAPSHOT_DIR / "vault_after_update.json"
KP_PASSWORD = "KpSnapshotPassword123!"


def golden_enabled() -> bool:
    """Whether to compare/update golden snapshots this run.

    Both CLI jobs set ``KP2BW_SNAPSHOT_GOLDEN`` to compare expected vault
    contents, in addition to the behavioral and idempotency checks.
    ``KP2BW_UPDATE_SNAPSHOTS`` enables regeneration and implies comparison.
    Both accept ``1``/``true``/``yes``/``on`` (see ``env_flag``).
    """
    return env_flag("KP2BW_SNAPSHOT_GOLDEN") or env_flag("KP2BW_UPDATE_SNAPSHOTS")


# --- deterministic binary fixtures ------------------------------------------
#
# Images/binaries are synthesized in-process (no committed binary, no Pillow) so
# the seed is one self-contained text file.  Bytes must be *byte-stable* across
# machines: the interpreter ships zlib-ng, whose ``zlib.compress`` output is not
# reproducible, so the PNG is built from stored (uncompressed) DEFLATE blocks
# plus the fixed-output Adler-32/CRC-32 checksums, which are identical anywhere.


def zlib_stored(raw: bytes) -> bytes:
    """A zlib stream of *stored* (uncompressed) DEFLATE blocks -- byte-stable."""
    out = bytearray(b"\x78\x01")  # zlib header (CM=deflate, no preset dict)
    total = len(raw)
    start = 0
    while True:
        block = raw[start : start + 0xFFFF]
        start += len(block)
        final = 1 if start >= total else 0
        out.append(final)  # BFINAL bit + BTYPE=00 (stored)
        length = len(block)
        out += struct.pack("<HH", length, length ^ 0xFFFF)  # LEN + NLEN
        out += block
        if final:
            break
    out += struct.pack(">I", zlib.adler32(raw) & 0xFFFFFFFF)
    return bytes(out)


def png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    """A minimal valid 8-bit truecolor PNG with byte-stable contents."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    row = b"\x00" + bytes(rgb) * width  # filter byte 0 + pixels
    idat = zlib_stored(row * height)
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# A tiny solid-blue 4x4 PNG and a 1 KiB blob covering every byte value.
LOGO_PNG = png(4, 4, (10, 132, 255))
BLOB = bytes(range(256)) * 4

# A custom-field value longer than this offloads to a <key>.txt attachment
# instead of an inline field (see convert.py); the seed exercises that path so a
# long field is never emitted both inline and as an attachment (#21).
LONG_FIELD = "BACKUP-CODE-" * 1000  # ~12k chars, comfortably over the 10k limit


def create_keepass_snapshot(path: Path, password: str) -> None:
    """Build a comprehensive, deterministic KeePass vault exercising every path.

    Covers: nested folders, plain logins, all TOTP shapes (KeePassXC otpauth URI
    passthrough, bare default-config Base32, Hex secret with SHA-256/8-digit
    config, and HOTP which has no Bitwarden equivalent), text/hidden custom
    fields, unicode, an empty password, and real binary + image attachments.
    """
    create_database(str(path), password=password)
    kp = PyKeePass(str(path), password=password)

    internet = kp.add_group(kp.root_group, "Internet")
    banking = kp.add_group(internet, "Banking")
    work = kp.add_group(kp.root_group, "Work")
    servers = kp.add_group(work, "Servers")

    # Example: KeePassXC-native TOTP with a non-default period -> migrates to
    # login.totp as an otpauth:// URI (not a bare secret) and must not leak into
    # custom fields.  (Existing #11 contract -- keep verbatim.)
    example = kp.add_entry(
        internet,
        "Example",
        "demo-user",
        "demo-pass",
        url="https://example.com",
        notes="seed note",
    )
    example.set_custom_property("api_token", "abc123")
    example.set_custom_property("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")
    example.set_custom_property("TimeOtp-Period", "60")

    # Root Entry: lives in the root group (no Bitwarden folder).
    _ = kp.add_entry(
        kp.root_group,
        "Root Entry",
        "root-user",
        "root-pass",
        notes="root note",
    )

    # Bank Account: a default-config Base32 secret round-trips as a *bare* secret
    # (friendlier than an otpauth URI); plus a hidden (protected) and a plain
    # custom field.
    bank = kp.add_entry(
        banking, "Bank Account", "bank-user", "bank-pass", url="https://bank.example"
    )
    bank.set_custom_property("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ")
    bank.set_custom_property("PIN", "1234", protect=True)
    bank.set_custom_property("branch", "downtown")

    # KeePassXC OTP: entry.otp is already an otpauth:// URI -> passthrough.
    # ('otp' is a reserved KeePass string field; use the setter, not
    # set_custom_property which rejects reserved keys.)
    xc = kp.add_entry(internet, "KeePassXC OTP", "xc-user", "xc-pass")
    xc.otp = "otpauth://totp/Issuer:xc-user?secret=GEZDGNBVGY3TQOJQ&issuer=Issuer&period=30&digits=6"

    # SSH Box: a Hex secret with SHA-256 + 8 digits -> otpauth:// URI carrying
    # algorithm/digits/period explicitly.
    ssh = kp.add_entry(servers, "SSH Box", "ssh-user", "ssh-pass", url="ssh://10.0.0.5")
    ssh.set_custom_property(
        "TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930"
    )
    ssh.set_custom_property("TimeOtp-Algorithm", "HMAC-SHA-256")
    ssh.set_custom_property("TimeOtp-Length", "8")

    # HOTP Legacy: counter-based HOTP has no time-based Bitwarden target, so the
    # secret is kept as a hidden custom field and login.totp stays empty.
    hotp = kp.add_entry(work, "HOTP Legacy", "hotp-user", "hotp-pass")
    hotp.set_custom_property("HmacOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", protect=True)

    # Unicode everywhere: title, username, password, url, notes, field value.
    cafe = kp.add_entry(
        internet,
        "Café ☕ Ünïcødé",
        "café-user",
        "naïve-pø$$wörd",
        url="https://例え.テスト",
        notes="naïve note — ünïcødé ✓",
    )
    cafe.set_custom_property("notiz", "geschützt", protect=True)

    # Has Files: real binary + image attachments (the headline gap).
    files = kp.add_entry(internet, "Has Files", "files-user", "files-pass")
    files.set_custom_property("label", "with attachments")
    logo_id = kp.add_binary(LOGO_PNG)
    files.add_attachment(logo_id, "logo.png")
    blob_id = kp.add_binary(BLOB)
    files.add_attachment(blob_id, "payload.bin")

    # Long Field: a custom field whose value tops the 10k inline limit must be
    # offloaded to a <key>.txt attachment *only*, never duplicated as an inline
    # field (#21). The short "hint" field beside it proves only the oversized
    # value is offloaded.
    long_field = kp.add_entry(internet, "Long Field", "long-user", "long-pass")
    long_field.set_custom_property("recovery_codes", LONG_FIELD)
    long_field.set_custom_property("hint", "see recovery_codes.txt")

    # Empty Password: a login with a username but no password.
    _ = kp.add_entry(kp.root_group, "Empty Password", "lonely-user", "")

    # Multi URL: exercises additional-URL -> login.uris folding end to end. The
    # KP2A_URL*/URL_*/AndroidApp* custom fields must NOT survive as fields; they
    # become login URIs with per-URI match modes -- plain -> account default
    # (match unset), double-quoted -> exact, trailing-path wildcard ->
    # starts-with, host wildcard -> regex -- plus androidapp:// for packages
    # (bare and the no-underscore AndroidApp1 variant). The keepassxc:// value is
    # a non-web scheme and is dropped entirely.
    multi = kp.add_entry(
        internet, "Multi URL", "multi-user", "multi-pass", url="https://multi.example"
    )
    multi.set_custom_property("KP2A_URL", "https://alt-one.example")
    multi.set_custom_property("KP2A_URL_1", "https://alt-two.example")
    multi.set_custom_property("URL_1", "https://alt-three.example")
    multi.set_custom_property("AndroidApp", "com.multi.app")
    multi.set_custom_property("AndroidApp1", "androidapp://com.multi.other")
    multi.set_custom_property("KP2A_URL_2", '"https://exact.example/login"')
    multi.set_custom_property("KP2A_URL_3", "https://multi.example/area/*")
    multi.set_custom_property("KP2A_URL_4", "https://*.wild.example/*")
    multi.set_custom_property("KP2A_URL_5", "keepassxc://by-uuid/dropme")

    kp.save()


# Notes longer than this migrate to a notes.txt attachment (see convert.py).
LONG_NOTE = "RECOVERY-KEY-" * 1000  # ~13k chars, comfortably over the 10k limit


def update_keepass_snapshot(path: Path, password: str) -> None:
    """Edit an existing snapshot to exercise the re-run update path (issue #11).

    Changes the Example entry's notes and password (credentials otherwise
    unchanged in spirit) and adds an entry whose notes exceed the attachment
    threshold, so a second migration must update the existing item and upload
    the long note as a notes.txt attachment.
    """
    kp = PyKeePass(str(path), password=password)

    example = kp.find_entries(title="Example", first=True)
    if example is None:
        raise AssertionError("Fixture contract broken: 'Example' entry not found")
    example.notes = "updated recovery keys"
    example.password = "demo-pass-v2"

    _ = kp.add_entry(
        kp.root_group,
        "Big Note",
        "big-user",
        "big-pass",
        notes=LONG_NOTE,
    )

    kp.save()


def create_ref_snapshot(path: Path, password: str) -> None:
    """Build a focused REF fixture for live TOTP/protection/idempotency checks."""
    create_database(str(path), password=password)
    kp = PyKeePass(str(path), password=password)

    target = kp.add_entry(
        kp.root_group,
        "REF Target",
        "ref-user",
        "ref-password",
        url="https://ref-target.example",
    )
    password_ref = f"{{REF:P@I:{target.uuid.hex.upper()}}}"

    alias = kp.add_entry(
        kp.root_group,
        "REF TOTP Alias",
        "ref-user",
        password_ref,
        url="https://ref-alias.example/v1",
    )
    alias.set_custom_property(
        "TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930"
    )
    alias.set_custom_property("TimeOtp-Algorithm", "HMAC-SHA-256")
    alias.set_custom_property("TimeOtp-Length", "8")

    distinct = kp.add_entry(
        kp.root_group,
        "REF Distinct",
        "different-ref-user",
        password_ref,
    )
    distinct.set_custom_property("private-code", "protected-value", protect=True)
    kp.save()


def update_ref_alias_url(path: Path, password: str) -> None:
    """Change only the merged REF alias URL to exercise sync-stamp updates."""
    kp = PyKeePass(str(path), password=password)
    alias = kp.find_entries(title="REF TOTP Alias", first=True)
    if alias is None:
        raise AssertionError("REF fixture contract broken: alias not found")
    alias.url = "https://ref-alias.example/v2"
    kp.save()


# A second long note (still over the 10k attachment threshold) used to verify
# that an *edited* attachment keeping the same filename is refreshed in place on
# a re-run instead of going stale or duplicating (issue #11).
LONG_NOTE_V2 = "ROTATED-SECRET-" * 1000  # ~15k chars, comfortably over the limit


def edit_refresh_note_snapshot(path: Path, password: str, new_notes: str) -> None:
    """Replace the Refresh Note entry's long note to exercise attachment refresh."""
    kp = PyKeePass(str(path), password=password)
    big = kp.find_entries(title="Refresh Note", first=True)
    if big is None:
        raise AssertionError("Fixture contract broken: 'Refresh Note' entry not found")
    big.notes = new_notes
    kp.save()


def convert(vault: Vault, snapshot_path: Path) -> None:
    converter = Converter(
        str(snapshot_path),
        KP_PASSWORD,
        None,
        vault.password,
        None,
        None,
        False,
        999,
        None,
        migrate_metadata=False,
    )
    if converter.convert(vault.client) != 0:
        raise AssertionError("In-process migration reported failures")


def capture_vault(vault: Vault) -> NormVault:
    """Snapshot the whole vault into a normalized, deterministic shape.

    The test requires a clean vault at the start (asserted in ``run_test``), so
    the whole vault *is* the migration output -- no exclusion needed.  Excluding
    pre-existing ids would be wrong here: an idempotent re-run updates matching
    items in place rather than creating new ones, so excluding them yields an
    empty snapshot.  Attachment bytes are downloaded and hashed; the hashes (not
    the bytes) land in the snapshot.
    """
    bw = vault.fresh()
    folder_names = {fid: name for name, fid in bw.list_folders().items()}
    raw_items: list[dict[str, JsonValue]] = []
    attachment_sha256: dict[str, str] = {}
    for brief in bw.list_items():
        item_id = brief["id"]
        full = bw.request("GET", f"/object/item/{item_id}")
        raw_items.append(full)
        for att in objects(full, "attachments"):
            attachment_id, file_name = opt_str(att, "id"), opt_str(att, "fileName")
            if attachment_id is None or file_name is None:
                raise TypeError("Attachment metadata has no id or file name")
            data = bw.get_attachment(item_id, attachment_id)
            attachment_sha256[attachment_key(item_id, file_name)] = hashlib.sha256(
                data
            ).hexdigest()
    return normalize_vault(
        raw_items, folder_names=folder_names, attachment_sha256=attachment_sha256
    )


def assert_snapshots_equal(first: NormVault, second: NormVault, *, label: str) -> None:
    """Assert two captured vaults are byte-identical once normalized."""
    left = canonical_json(first)
    right = canonical_json(second)
    if left == right:
        return
    diff = "".join(
        difflib.unified_diff(
            left.splitlines(keepends=True),
            right.splitlines(keepends=True),
            fromfile="first",
            tofile="second",
        )
    )
    raise AssertionError(f"{label}: normalized vault differs between passes:\n{diff}")


def item_by_name(vault: NormVault, name: str) -> NormItem:
    """Return the single migrated item with this name (names are unique in the seed)."""
    matches = [item for item in vault["items"] if item["name"] == name]
    if len(matches) != 1:
        names = sorted(str(item["name"]) for item in vault["items"])
        raise AssertionError(
            f"expected exactly one item named {name!r}, found {len(matches)} "
            f"(items: {names})"
        )
    return matches[0]


def make_login(item: NormItem) -> NormLogin:
    login = item["login"]
    if login is None:
        raise AssertionError(f"item {item['name']!r} has no login")
    return login


def find_field(item: NormItem, name: str) -> NormField:
    matches = [field for field in item["fields"] if field["name"] == name]
    if len(matches) != 1:
        raise AssertionError(
            f"item {item['name']!r}: expected one field {name!r}, found {len(matches)}"
        )
    return matches[0]


def assert_live_ref_items(
    vault: Vault, *, alias_url: str
) -> dict[str, tuple[str, str]]:
    """Assert the focused REF fixture directly against live Bitwarden items."""
    items = vault.items()
    if any(item.get("name") == "REF TOTP Alias" for item in items):
        raise AssertionError("credential-matching REF alias was imported separately")
    listed = vault.named("REF Target", "REF Distinct")

    def full_item(name: str) -> BwItemResponse:
        return vault.client.get_item(listed[name]["id"])

    target = full_item("REF Target")
    target_login = target.get("login")
    if target_login is None:
        raise TypeError("REF Target has no login")
    uri_values = {uri["uri"] for uri in target_login.get("uris") or []}
    expected_uris = {"https://ref-target.example", alias_url}
    if uri_values != expected_uris:
        raise AssertionError("REF Target does not carry the expected merged URIs")

    totp = target_login.get("totp")
    if not isinstance(totp, str) or not totp.startswith("otpauth://totp/"):
        raise AssertionError("REF Target did not receive the alias TOTP")
    if "algorithm=SHA256" not in totp or "digits=8" not in totp:
        raise AssertionError("REF Target TOTP lost its non-default configuration")

    distinct = full_item("REF Distinct")
    private_types = [
        field.get("type")
        for field in distinct.get("fields") or []
        if field.get("name") == "private-code"
    ]
    if private_types != [1]:
        raise AssertionError("REF Distinct protected field is not hidden")

    versions: dict[str, tuple[str, str]] = {}
    for name, item in (("REF Target", target), ("REF Distinct", distinct)):
        revision = item.get("revisionDate")
        if not revision:
            raise TypeError(f"live item {name!r} has no revision")
        versions[name] = (item["id"], revision)
    return versions


def assert_comprehensive_seed(vault: NormVault) -> None:
    """Behavioral assertions over the initial snapshot.

    These overlap with the golden but give a sharp, named failure when a
    specific migration contract (a TOTP form, a hidden field, an attachment's
    bytes) regresses -- clearer than reading a golden diff.
    """
    # Bare default-config Base32 secret (not an otpauth URI).
    bank = item_by_name(vault, "Bank Account")
    bank_totp = make_login(bank)["totp"] or ""
    if bank_totp.startswith("otpauth://") or "GEZDGNBVGY3TQOJQ" not in bank_totp:
        raise AssertionError(
            f"Bank Account TOTP should be a bare secret: {bank_totp!r}"
        )
    if find_field(bank, "PIN")["type"] != 1:
        raise AssertionError("Bank Account 'PIN' should be a hidden field (type 1)")
    if find_field(bank, "branch")["type"] != 0:
        raise AssertionError("Bank Account 'branch' should be a text field (type 0)")

    # Hex secret + SHA-256 + 8 digits -> otpauth URI carrying those params.
    ssh_totp = make_login(item_by_name(vault, "SSH Box"))["totp"] or ""
    if not ssh_totp.startswith("otpauth://totp/"):
        raise AssertionError(f"SSH Box TOTP should be an otpauth URI: {ssh_totp!r}")
    if "algorithm=SHA256" not in ssh_totp or "digits=8" not in ssh_totp:
        raise AssertionError(
            f"SSH Box TOTP missing SHA256/8-digit config: {ssh_totp!r}"
        )

    # KeePassXC otp passthrough keeps the original secret.
    xc_totp = make_login(item_by_name(vault, "KeePassXC OTP"))["totp"] or ""
    if (
        not xc_totp.startswith("otpauth://totp/")
        or "secret=GEZDGNBVGY3TQOJQ" not in xc_totp
    ):
        raise AssertionError(f"KeePassXC OTP passthrough wrong: {xc_totp!r}")

    # HOTP has no Bitwarden TOTP target: empty login.totp, secret kept hidden.
    hotp = item_by_name(vault, "HOTP Legacy")
    if make_login(hotp)["totp"]:
        raise AssertionError("HOTP Legacy must not produce a login.totp")
    if find_field(hotp, "HmacOtp-Secret-Base32")["type"] != 1:
        raise AssertionError("HOTP secret should be kept as a hidden field (type 1)")

    # Real binary + image attachments must round-trip byte-for-byte.
    files = item_by_name(vault, "Has Files")
    by_name = {att["fileName"]: att["sha256"] for att in files["attachments"]}
    if by_name.get("logo.png") != hashlib.sha256(LOGO_PNG).hexdigest():
        raise AssertionError("logo.png attachment bytes did not round-trip")
    if by_name.get("payload.bin") != hashlib.sha256(BLOB).hexdigest():
        raise AssertionError("payload.bin attachment bytes did not round-trip")

    # Unicode credentials survive the round-trip intact.
    cafe = make_login(item_by_name(vault, "Café ☕ Ünïcødé"))
    if cafe["username"] != "café-user" or cafe["password"] != "naïve-pø$$wörd":
        raise AssertionError("Unicode credentials were corrupted in migration")

    # A >10k custom field is offloaded to a <key>.txt attachment *only* -- never
    # also stored inline, which would duplicate it and can hit the field-size
    # limit (#21). The short field beside it still migrates inline.
    long_field = item_by_name(vault, "Long Field")
    long_atts = {att["fileName"]: att["sha256"] for att in long_field["attachments"]}
    if (
        long_atts.get("recovery_codes.txt")
        != hashlib.sha256(LONG_FIELD.encode("UTF-8")).hexdigest()
    ):
        raise AssertionError(
            "Long custom field was not offloaded to recovery_codes.txt intact"
        )
    if any(field["name"] == "recovery_codes" for field in long_field["fields"]):
        raise AssertionError(
            "Long custom field must not also be emitted as an inline field (#21)"
        )
    if find_field(long_field, "hint")["value"] != "see recovery_codes.txt":
        raise AssertionError("Short field beside the long one should stay inline")

    # Additional URLs / Android packages fold into login.uris with per-URI match
    # modes; the KP2A_URL*/URL_*/AndroidApp* custom fields must NOT survive, and
    # the keepassxc:// value must be dropped. (Runs unconditionally, so the
    # non-golden CI leg validates the fold too.)
    multi = item_by_name(vault, "Multi URL")
    multi_uri_list = make_login(multi)["uris"]
    multi_uri_values = [uri["uri"] for uri in multi_uri_list]
    if len(set(multi_uri_values)) != len(multi_uri_values):
        raise AssertionError(f"Multi URL has duplicate URIs: {multi_uri_values}")
    multi_uris = {uri["uri"]: uri["match"] for uri in multi_uri_list}
    expected_multi_uris: dict[str, int | None] = {
        "https://multi.example": None,
        "https://alt-one.example": None,
        "https://alt-two.example": None,
        "https://alt-three.example": None,
        "androidapp://com.multi.app": None,
        "androidapp://com.multi.other": None,
        "https://exact.example/login": 3,  # quoted -> exact
        "https://multi.example/area/": 2,  # trailing wildcard -> starts-with
        "https://.*\\.wild\\.example/.*": 4,  # host wildcard -> regex
    }
    if multi_uris != expected_multi_uris:
        raise AssertionError(f"Multi URL uris/match wrong: {multi_uris}")
    leftover = [
        name
        for field in multi["fields"]
        if is_url_attribute_key(name := field["name"] or "")
    ]
    if leftover:
        raise AssertionError(f"Multi URL still carries legacy URL fields: {leftover}")


def run_golden_test(vault: Vault) -> None:
    tmp = vault.tmp
    logger.info(
        "Using %s %s against %s",
        vault.env.get("KP2BW_TEST_CLI_PACKAGE", "@bitwarden/cli"),
        vault.client.cli_version,
        vault.account.server,
    )
    before_items = vault.items()
    # Golden snapshots capture the whole vault, so the run must start clean.
    if before_items:
        raise AssertionError(
            f"e2e requires a clean Vaultwarden vault but found {len(before_items)} "
            "items. Recreate the server (e.g. `docker compose -f tests/"
            "docker-compose.yml down -v`) before running."
        )

    snapshot_path = tmp / "snapshot.kdbx"
    create_keepass_snapshot(snapshot_path, KP_PASSWORD)

    logger.info("Running kp2bw migration (first pass)")
    convert(vault, snapshot_path)
    s1 = capture_vault(vault)
    logger.info(f"First pass migrated {len(s1['items'])} items")

    logger.info("Running idempotency pass")
    convert(vault, snapshot_path)
    s2 = capture_vault(vault)

    # The headline reproducibility proof: a second migration with an
    # unchanged source must produce a byte-identical normalized vault.
    assert_snapshots_equal(s1, s2, label="idempotency (pass 1 vs pass 2)")

    if golden_enabled():
        assert_matches_golden(s2, GOLDEN_INITIAL)
        logger.info("Initial vault snapshot matches golden")

    # Sharp, named behavioral checks over the comprehensive seed.
    assert_comprehensive_seed(s2)

    # --- Existing #11 contract checks (kept verbatim in spirit) ----------
    if "Internet" not in vault.client.list_folders():
        raise AssertionError("Expected folder 'Internet' not found in Bitwarden")

    example = item_by_name(s2, "Example")
    example_login = make_login(example)
    if (
        example_login["username"] != "demo-user"
        or example_login["password"] != "demo-pass"
    ):
        raise AssertionError("Example item credentials were not migrated correctly")
    if not any(uri["uri"] == "https://example.com" for uri in example_login["uris"]):
        raise AssertionError("Example item URL was not migrated correctly")
    if find_field(example, "api_token")["value"] != "abc123":
        raise AssertionError("Expected custom field api_token=abc123 not found")
    example_totp = example_login["totp"] or ""
    if not example_totp.startswith("otpauth://totp/"):
        raise AssertionError(
            f"Expected an otpauth TOTP URI on Example, got {example_totp!r}"
        )
    if "secret=JBSWY3DPEHPK3PXP" not in example_totp or "period=60" not in example_totp:
        raise AssertionError(
            f"TOTP URI missing expected secret/period: {example_totp!r}"
        )
    leaked = [
        field["name"]
        for field in example["fields"]
        if field["name"] in {"TimeOtp-Secret-Base32", "TimeOtp-Period"}
    ]
    if leaked:
        raise AssertionError(
            f"TOTP fields leaked into custom fields instead of login.totp: {leaked}"
        )

    root_login = make_login(item_by_name(s2, "Root Entry"))
    if root_login["username"] != "root-user" or root_login["password"] != "root-pass":
        raise AssertionError("Root Entry credentials were not migrated correctly")

    # --- Update pass: edit KeePass, re-run, verify the changes sync ------
    logger.info("Editing KeePass snapshot and running update pass")
    update_keepass_snapshot(snapshot_path, KP_PASSWORD)
    convert(vault, snapshot_path)
    s3 = capture_vault(vault)

    if golden_enabled():
        assert_matches_golden(s3, GOLDEN_AFTER_UPDATE)
        logger.info("Post-update vault snapshot matches golden")

    # Existing "Example" entry must be updated in place, not duplicated.
    example = item_by_name(s3, "Example")
    if example["notes"] != "updated recovery keys":
        raise AssertionError(
            f"Edited notes were not synced to Bitwarden: {example['notes']!r}"
        )
    if make_login(example)["password"] != "demo-pass-v2":
        raise AssertionError("Edited password was not synced to Bitwarden")

    # The long-note entry must store its note as a notes.txt attachment.
    big = item_by_name(s3, "Big Note")
    if not any(att["fileName"] == "notes.txt" for att in big["attachments"]):
        raise AssertionError(
            f"Long note was not uploaded as a notes.txt attachment: {big['attachments']}"
        )
    if len(big["notes"] or "") > 10 * 1000:
        raise AssertionError("Long note should be offloaded to the attachment")

    big_id = vault.named("Big Note")["Big Note"]["id"]
    if vault.attachment(big_id, "notes.txt") != LONG_NOTE.encode():
        raise AssertionError(
            "notes.txt attachment content does not match the original long note"
        )

    convert(vault, snapshot_path)
    s4 = capture_vault(vault)
    assert_snapshots_equal(s3, s4, label="idempotency (updated state)")
    print("golden migration, idempotency and update regression passed")


def run_attachment_refresh_test(vault: Vault) -> None:
    snapshot_path = vault.tmp / "refresh.kdbx"
    create_database(str(snapshot_path), password=KP_PASSWORD)
    kp = PyKeePass(str(snapshot_path), password=KP_PASSWORD)
    _ = kp.add_entry(
        kp.root_group, "Refresh Note", "big-user", "big-pass", notes=LONG_NOTE
    )
    kp.save()
    convert(vault, snapshot_path)
    big_id = vault.named("Refresh Note")["Refresh Note"]["id"]
    if vault.attachment(big_id, "notes.txt") != LONG_NOTE.encode():
        raise AssertionError(
            "notes.txt attachment content does not match the original long note"
        )

    # --- Attachment refresh: edit the long note (same filename) and re-run.
    # The notes.txt attachment must be replaced with the new content and the
    # stale copy removed -- not left as a duplicate (content-aware sync, #11).
    logger.info("Editing Refresh Note's long note and running attachment-refresh pass")
    edit_refresh_note_snapshot(snapshot_path, KP_PASSWORD, LONG_NOTE_V2)
    convert(vault, snapshot_path)

    big_after_refresh = [i for i in vault.items() if i.get("name") == "Refresh Note"]
    if len(big_after_refresh) != 1 or big_after_refresh[0]["id"] != big_id:
        raise AssertionError(
            f"Attachment-refresh re-run must not duplicate 'Refresh Note': {big_after_refresh}"
        )
    notes_copies = [
        att
        for att in vault.client.get_item(big_id).get("attachments") or []
        if att["fileName"] == "notes.txt"
    ]
    if len(notes_copies) != 1:
        raise AssertionError(
            f"Refreshed attachment must replace, not duplicate: {notes_copies}"
        )
    if vault.attachment(big_id, "notes.txt") != LONG_NOTE_V2.encode():
        raise AssertionError(
            "notes.txt attachment was not refreshed with the edited long note"
        )

    # Final idempotent re-run (no edits) must change nothing.
    s_refresh = capture_vault(vault)
    convert(vault, snapshot_path)
    s_final = capture_vault(vault)
    assert_snapshots_equal(s_refresh, s_final, label="idempotency (refreshed state)")
    print("attachment refresh and idempotency regression passed")


def run_ref_test(vault: Vault) -> None:
    # Focused REF passes stay out of the comprehensive snapshot contract.
    ref_snapshot_path = vault.tmp / "refs.kdbx"
    create_ref_snapshot(ref_snapshot_path, KP_PASSWORD)
    logger.info("Running focused REF migration")
    convert(vault, ref_snapshot_path)
    ref_v1 = assert_live_ref_items(vault, alias_url="https://ref-alias.example/v1")

    # Unchanged REF re-run must issue no item PUT and create no duplicate.
    convert(vault, ref_snapshot_path)
    ref_v1_rerun = assert_live_ref_items(
        vault, alias_url="https://ref-alias.example/v1"
    )
    if ref_v1_rerun != ref_v1:
        raise AssertionError("Unchanged REF re-run changed item revisions")

    # A later alias URL edit must update normally. A stale KP2BW_SYNC stamp
    # would misclassify the canonical item as manually edited and block this.
    update_ref_alias_url(ref_snapshot_path, KP_PASSWORD)
    convert(vault, ref_snapshot_path)
    ref_v2 = assert_live_ref_items(vault, alias_url="https://ref-alias.example/v2")

    # The updated REF state must also settle into a no-PUT idempotent re-run.
    convert(vault, ref_snapshot_path)
    ref_v2_rerun = assert_live_ref_items(
        vault, alias_url="https://ref-alias.example/v2"
    )
    if ref_v2_rerun != ref_v2:
        raise AssertionError("Updated REF re-run changed item revisions")
    print("live REF merge, TOTP, protection and idempotency regression passed")


# Goldens run first: they require a clean vault. Scope fixtures run after the
# personal checks so their organization items never enter personal assertions.
SUITE: dict[str, Callable[[Vault], None]] = {
    "golden": run_golden_test,
    "attachment_refresh": run_attachment_refresh_test,
    "refs": run_ref_test,
    "metadata": run_metadata_test,
    "metadata_legacy_ref": run_metadata_legacy_ref_test,
    "reserved_fields": run_reserved_fields_test,
    "ssh_cli": run_ssh_cli_test,
    "ssh": run_ssh_test,
    "ssh_rotation": run_ssh_rotation_test,
    "ssh_protected": run_ssh_protected_test,
    "checkpoint": run_checkpoint_test,
    **{f"crash_{mode.replace('-', '_')}": crash_check(mode) for mode in CRASH_MODES},
    "passkey": run_passkey_test,
    "preview": run_preview_test,
    "preview_update": run_preview_update_test,
    "preview_protected": run_preview_protected_test,
    "preview_resume": run_preview_resume_test,
    "preview_resume_converge": run_preview_resume_converge_test,
    "attachment_batch": run_attachment_batch_test,
    "attachment_identity": run_attachment_identity_test,
    "attachment_rejected": run_attachment_rejected_test,
    "attachment_added": run_attachment_added_test,
    "attachment_legacy": run_attachment_legacy_test,
    "templates_cli": run_templates_cli_test,
    "templates": run_templates_test,
    "templates_selected": run_templates_selected_test,
    "history_archive_cli": run_history_archive_cli_test,
    "history_archive": run_history_archive_test,
    "history_updates": run_history_updates_test,
    "field_limits": run_field_limits_test,
    "field_limits_org": run_field_limits_org_test,
    "scope": run_scope_test,
    "scope_report": run_scope_report_test,
    "scope_migrate_uris": run_scope_migrate_uris_test,
    "scope_strip": run_scope_strip_test,
    "item_selection": run_item_selection_test,
    "item_selection_force": run_item_selection_force_test,
    "item_selection_rejected": run_item_selection_rejected_test,
    "fixups": run_fixups_test,
    "fixups_uri_only": run_fixups_uri_only_test,
    "fixups_personal": run_fixups_personal_test,
}


def main(names: list[str] | None = None) -> None:
    names = names or list(SUITE)
    unknown = [name for name in names if name not in SUITE]
    if unknown:
        raise SystemExit(f"Unknown end-to-end checks: {', '.join(unknown)}")

    def run_suite(vault: Vault) -> None:
        for name, check in SUITE.items():
            if name in names:
                check(vault)

    vault_main(run_suite)
    print("vaultwarden end-to-end integration test passed")


if __name__ == "__main__":
    main(sys.argv[1:])
