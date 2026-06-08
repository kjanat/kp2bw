import difflib
import hashlib
import json
import logging
import os
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import cast

from _snapshot import (
    JsonValue,
    NormField,
    NormItem,
    NormLogin,
    NormVault,
    as_object,
    assert_matches_golden,
    attachment_key,
    canonical_json,
    normalize_vault,
    parse_object,
)
from pykeepass import Entry, PyKeePass, create_database

logger = logging.getLogger("e2e")

SENSITIVE_ARG_FLAGS = {
    "--bitwarden-password",
    "--keepass-password",
    "--passwordenv",
    "--session",
}

_SNAPSHOT_DIR = Path(__file__).resolve().parent / "__snapshots__"
GOLDEN_INITIAL = _SNAPSHOT_DIR / "vault_initial.json"
GOLDEN_AFTER_UPDATE = _SNAPSHOT_DIR / "vault_after_update.json"


def _golden_enabled() -> bool:
    """Whether to compare/update golden snapshots this run.

    The pinned-CLI matrix leg sets ``KP2BW_SNAPSHOT_GOLDEN=1`` and owns the
    golden; the ``latest`` leg leaves it unset and runs behavioral + idempotency
    checks only, so an upstream ``bw`` release that reshapes the JSON cannot
    redden CI on its own.  ``KP2BW_UPDATE_SNAPSHOTS=1`` (regeneration) implies it.
    """
    return (
        os.environ.get("KP2BW_SNAPSHOT_GOLDEN") == "1"
        or os.environ.get("KP2BW_UPDATE_SNAPSHOTS") == "1"
    )


def _collect_sensitive_values(command: list[str]) -> tuple[str, ...]:
    """Collect sensitive CLI values from command arguments."""
    values: list[str] = []
    for i, arg in enumerate(command[:-1]):
        if arg in SENSITIVE_ARG_FLAGS:
            values.append(command[i + 1])
    return tuple(values)


def _redact_output(output: str, *, command: list[str], secrets: tuple[str, ...]) -> str:
    """Redact sensitive values from command output."""
    if not output:
        return output

    if "--raw" in command:
        return "[redacted raw output]"

    redacted = output
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    timeout: float = 300,
) -> str:
    secrets = _collect_sensitive_values(command)

    # Redact sensitive values from log output
    safe_cmd = " ".join(
        "***" if i > 0 and command[i - 1] in SENSITIVE_ARG_FLAGS else arg
        for i, arg in enumerate(command)
    )
    logger.info(f"Running: {safe_cmd}")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # exc.stdout/stderr may be bytes even with text=True on some versions
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stdout = _redact_output(stdout, command=command, secrets=secrets)
        stderr = _redact_output(stderr, command=command, secrets=secrets)
        raise AssertionError(
            f"Command timed out after {timeout}s: {safe_cmd}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        ) from exc
    if result.returncode != 0:
        stdout = _redact_output(result.stdout, command=command, secrets=secrets)
        stderr = _redact_output(result.stderr, command=command, secrets=secrets)
        raise AssertionError(
            f"Command failed ({result.returncode}): {safe_cmd}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )
    logger.debug(f"  stdout chars: {len(result.stdout)}")
    return result.stdout.strip()


def _bw_json(env: dict[str, str], *args: str) -> list[dict[str, JsonValue]]:
    output = _run(["bw", *args], env=env)
    try:
        data: JsonValue = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Expected JSON output from bw command {' '.join(args)}, got:\n{output}"
        ) from exc
    if not isinstance(data, list):
        raise TypeError(f"Expected a JSON array from bw {' '.join(args)}")
    return [as_object(entry) for entry in data]


def _get_session(env: dict[str, str], password: str) -> str:
    """Unlock the vault and return a session token.

    Tries ``bw unlock --raw`` first.  If that returns empty (which can happen
    with recent CLI versions when the vault is already unlocked after login),
    falls back to locking then unlocking.
    """
    pw_env = env.copy()
    pw_env["BW_PASSWORD"] = password

    for _ in range(3):
        session = _run(
            ["bw", "unlock", "--raw", "--passwordenv", "BW_PASSWORD"],
            env=pw_env,
        )
        if session:
            return session

        # Lock first so the next unlock has something to do.
        _ = _run(["bw", "lock"], env=env)

    status = _run(["bw", "status"], env=env)
    raise AssertionError(
        f"bw unlock returned an empty session token after retries. bw status: {status}"
    )


def _login_session(env: dict[str, str], email: str, password: str) -> str:
    """Log in and return the session token in a single step."""
    pw_env = env.copy()
    pw_env["BW_PASSWORD"] = password

    session = _run(
        ["bw", "login", email, "--passwordenv", "BW_PASSWORD", "--raw"],
        env=pw_env,
    )
    if session:
        return session

    # Fallback: login may have succeeded without --raw returning a token.
    # Try unlocking instead.
    return _get_session(env, password)


# --- deterministic binary fixtures ------------------------------------------
#
# Images/binaries are synthesized in-process (no committed binary, no Pillow) so
# the seed is one self-contained text file.  Bytes must be *byte-stable* across
# machines: the interpreter ships zlib-ng, whose ``zlib.compress`` output is not
# reproducible, so the PNG is built from stored (uncompressed) DEFLATE blocks
# plus the fixed-output Adler-32/CRC-32 checksums, which are identical anywhere.


def _zlib_stored(raw: bytes) -> bytes:
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


def _png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
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
    idat = _zlib_stored(row * height)
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# A tiny solid-blue 4x4 PNG and a 1 KiB blob covering every byte value.
_LOGO_PNG = _png(4, 4, (10, 132, 255))
_BLOB = bytes(range(256)) * 4


def _create_keepass_snapshot(path: Path, password: str) -> None:
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
    logo_id = kp.add_binary(_LOGO_PNG)
    files.add_attachment(logo_id, "logo.png")
    blob_id = kp.add_binary(_BLOB)
    files.add_attachment(blob_id, "payload.bin")

    # Empty Password: a login with a username but no password.
    _ = kp.add_entry(kp.root_group, "Empty Password", "lonely-user", "")

    kp.save()


# Notes longer than this migrate to a notes.txt attachment (see convert.py).
LONG_NOTE = "RECOVERY-KEY-" * 1000  # ~13k chars, comfortably over the 10k limit


def _update_keepass_snapshot(path: Path, password: str) -> None:
    """Edit an existing snapshot to exercise the re-run update path (issue #11).

    Changes the Example entry's notes and password (credentials otherwise
    unchanged in spirit) and adds an entry whose notes exceed the attachment
    threshold, so a second migration must update the existing item and upload
    the long note as a notes.txt attachment.
    """
    kp = PyKeePass(str(path), password=password)

    # find_entries(first=True) is typed list|Entry|None. Fail fast with a clear
    # message if the snapshot's Example entry is missing, then narrow to Entry.
    found = kp.find_entries(title="Example", first=True)
    if found is None:
        raise AssertionError("Fixture contract broken: 'Example' entry not found")
    example = cast(Entry, found)
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


# A second long note (still over the 10k attachment threshold) used to verify
# that an *edited* attachment keeping the same filename is refreshed in place on
# a re-run instead of going stale or duplicating (issue #11).
LONG_NOTE_V2 = "ROTATED-SECRET-" * 1000  # ~15k chars, comfortably over the limit


def _edit_big_note_snapshot(path: Path, password: str, new_notes: str) -> None:
    """Replace the Big Note entry's long note to exercise attachment refresh."""
    kp = PyKeePass(str(path), password=password)
    found = kp.find_entries(title="Big Note", first=True)
    if found is None:
        raise AssertionError("Fixture contract broken: 'Big Note' entry not found")
    big = cast(Entry, found)
    big.notes = new_notes
    kp.save()


def _get_attachment_text(
    env: dict[str, str], session: str, item_id: str, file_name: str
) -> str:
    """Download a named attachment's decrypted text via the bw CLI."""
    return _run(
        [
            "bw",
            "get",
            "attachment",
            file_name,
            "--itemid",
            item_id,
            "--raw",
            "--session",
            session,
        ],
        env=env,
    )


def _download_attachment(
    env: dict[str, str],
    session: str,
    item_id: str,
    file_name: str,
    dest_dir: Path,
) -> bytes:
    """Download an attachment to a file and return its raw bytes.

    Uses ``--output`` (not ``--raw`` to stdout) so binary content is written by
    the CLI without any text-mode/locale corruption -- essential for images and
    arbitrary blobs.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Item ids are unique; prefixing avoids cross-item filename collisions.
    dest = dest_dir / f"{item_id}__{file_name}"
    _ = _run(
        [
            "bw",
            "get",
            "attachment",
            file_name,
            "--itemid",
            item_id,
            "--session",
            session,
            "--output",
            str(dest),
        ],
        env=env,
    )
    return dest.read_bytes()


def _run_migration(
    snapshot_path: Path,
    kp_password: str,
    bw_password: str,
    env: dict[str, str],
) -> str:
    """Run a single kp2bw migration pass against the snapshot."""
    return _run(
        [
            "uv",
            "run",
            "kp2bw",
            str(snapshot_path),
            "--keepass-password",
            kp_password,
            "--bitwarden-password",
            bw_password,
            "--path-to-name-skip",
            "999",
            "--no-metadata",
            "-y",
            "-v",
        ],
        env=env,
    )


def _assert_bw_serve_available(env: dict[str, str]) -> None:
    """Verify the bw CLI supports ``bw serve`` (required by the new transport)."""
    result = subprocess.run(
        ["bw", "serve", "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(
            "bw serve is not available. kp2bw v3 requires bw CLI with serve support.\n"
            f"stderr: {result.stderr}"
        )


def _capture_vault(
    env: dict[str, str],
    session: str,
    *,
    download_dir: Path,
) -> NormVault:
    """Snapshot the whole vault into a normalized, deterministic shape.

    The test requires a clean vault at the start (asserted in ``main``), so the
    whole vault *is* the migration output -- no exclusion needed.  Excluding
    pre-existing ids would be wrong here: an idempotent re-run updates matching
    items in place rather than creating new ones, so excluding them yields an
    empty snapshot.  Attachment bytes are downloaded and hashed; the hashes (not
    the bytes) land in the snapshot.
    """
    folders = _bw_json(env, "list", "folders", "--session", session)
    folder_names: dict[str, str] = {}
    for folder in folders:
        fid = folder.get("id")
        fname = folder.get("name")
        if isinstance(fid, str) and isinstance(fname, str):
            folder_names[fid] = fname

    items = _bw_json(env, "list", "items", "--session", session)
    raw_items: list[dict[str, JsonValue]] = []
    attachment_sha256: dict[str, str] = {}
    for brief in items:
        item_id = brief.get("id")
        if not isinstance(item_id, str):
            continue
        full = parse_object(
            _run(["bw", "get", "item", item_id, "--session", session], env=env)
        )
        raw_items.append(full)
        attachments = full.get("attachments")
        if not isinstance(attachments, list):
            continue
        for att in attachments:
            file_name = as_object(att).get("fileName")
            if not isinstance(file_name, str):
                continue
            data = _download_attachment(env, session, item_id, file_name, download_dir)
            attachment_sha256[attachment_key(item_id, file_name)] = hashlib.sha256(
                data
            ).hexdigest()

    return normalize_vault(
        raw_items, folder_names=folder_names, attachment_sha256=attachment_sha256
    )


def _assert_snapshots_equal(first: NormVault, second: NormVault, *, label: str) -> None:
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


def _item_by_name(vault: NormVault, name: str) -> NormItem:
    """Return the single migrated item with this name (names are unique in the seed)."""
    matches = [item for item in vault["items"] if item["name"] == name]
    if len(matches) != 1:
        names = sorted(str(item["name"]) for item in vault["items"])
        raise AssertionError(
            f"expected exactly one item named {name!r}, found {len(matches)} "
            f"(items: {names})"
        )
    return matches[0]


def _login(item: NormItem) -> NormLogin:
    login = item["login"]
    if login is None:
        raise AssertionError(f"item {item['name']!r} has no login")
    return login


def _field(item: NormItem, name: str) -> NormField:
    matches = [field for field in item["fields"] if field["name"] == name]
    if len(matches) != 1:
        raise AssertionError(
            f"item {item['name']!r}: expected one field {name!r}, found {len(matches)}"
        )
    return matches[0]


def _assert_comprehensive_seed(vault: NormVault) -> None:
    """Behavioral assertions over the initial snapshot.

    These overlap with the golden but give a sharp, named failure when a
    specific migration contract (a TOTP form, a hidden field, an attachment's
    bytes) regresses -- clearer than reading a golden diff.
    """
    # Bare default-config Base32 secret (not an otpauth URI).
    bank = _item_by_name(vault, "Bank Account")
    bank_totp = _login(bank)["totp"] or ""
    if bank_totp.startswith("otpauth://") or "GEZDGNBVGY3TQOJQ" not in bank_totp:
        raise AssertionError(
            f"Bank Account TOTP should be a bare secret: {bank_totp!r}"
        )
    if _field(bank, "PIN")["type"] != 1:
        raise AssertionError("Bank Account 'PIN' should be a hidden field (type 1)")
    if _field(bank, "branch")["type"] != 0:
        raise AssertionError("Bank Account 'branch' should be a text field (type 0)")

    # Hex secret + SHA-256 + 8 digits -> otpauth URI carrying those params.
    ssh_totp = _login(_item_by_name(vault, "SSH Box"))["totp"] or ""
    if not ssh_totp.startswith("otpauth://totp/"):
        raise AssertionError(f"SSH Box TOTP should be an otpauth URI: {ssh_totp!r}")
    if "algorithm=SHA256" not in ssh_totp or "digits=8" not in ssh_totp:
        raise AssertionError(
            f"SSH Box TOTP missing SHA256/8-digit config: {ssh_totp!r}"
        )

    # KeePassXC otp passthrough keeps the original secret.
    xc_totp = _login(_item_by_name(vault, "KeePassXC OTP"))["totp"] or ""
    if (
        not xc_totp.startswith("otpauth://totp/")
        or "secret=GEZDGNBVGY3TQOJQ" not in xc_totp
    ):
        raise AssertionError(f"KeePassXC OTP passthrough wrong: {xc_totp!r}")

    # HOTP has no Bitwarden TOTP target: empty login.totp, secret kept hidden.
    hotp = _item_by_name(vault, "HOTP Legacy")
    if _login(hotp)["totp"]:
        raise AssertionError("HOTP Legacy must not produce a login.totp")
    if _field(hotp, "HmacOtp-Secret-Base32")["type"] != 1:
        raise AssertionError("HOTP secret should be kept as a hidden field (type 1)")

    # Real binary + image attachments must round-trip byte-for-byte.
    files = _item_by_name(vault, "Has Files")
    by_name = {att["fileName"]: att["sha256"] for att in files["attachments"]}
    if by_name.get("logo.png") != hashlib.sha256(_LOGO_PNG).hexdigest():
        raise AssertionError("logo.png attachment bytes did not round-trip")
    if by_name.get("payload.bin") != hashlib.sha256(_BLOB).hexdigest():
        raise AssertionError("payload.bin attachment bytes did not round-trip")

    # Unicode credentials survive the round-trip intact.
    cafe = _login(_item_by_name(vault, "Café ☕ Ünïcødé"))
    if cafe["username"] != "café-user" or cafe["password"] != "naïve-pø$$wörd":
        raise AssertionError("Unicode credentials were corrupted in migration")


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        level=logging.INFO,
    )
    logger.setLevel(logging.DEBUG)

    repo_root = Path(__file__).resolve().parents[1]
    cert_path = Path(
        os.environ.get(
            "BW_CERT_PATH", str(repo_root / "tests/fixtures/vaultwarden-certs/cert.pem")
        )
    )
    server_url = os.environ.get("BW_SERVER_URL", "https://localhost:18443")
    bw_email = os.environ.get("BW_TEST_EMAIL", "integration@example.com")
    bw_password = os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!")
    kp_password = os.environ.get("KP_TEST_PASSWORD", "KpSnapshotPassword123!")

    if not cert_path.exists():
        raise AssertionError(f"Missing cert file: {cert_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        appdata = tmp / "bw-appdata"
        appdata.mkdir(parents=True, exist_ok=True)
        downloads = tmp / "downloads"

        env = os.environ.copy()
        env["BITWARDENCLI_APPDATA_DIR"] = str(appdata)
        env["NODE_EXTRA_CA_CERTS"] = str(cert_path)

        logger.info("Checking bw serve availability")
        _assert_bw_serve_available(env)
        _ = _run(["bw", "config", "server", server_url], env=env)

        logger.info("Logging in to Bitwarden")
        initial_session = _login_session(env, bw_email, bw_password)
        logger.info("Listing pre-migration items")
        before_items = _bw_json(env, "list", "items", "--session", initial_session)
        logger.info(f"Found {len(before_items)} existing items")
        # Golden snapshots capture the whole vault, so the run must start clean.
        # A fresh Vaultwarden container (CI host-mode / `docker compose down -v`)
        # guarantees this; fail loudly rather than bake a polluted golden.
        if before_items:
            raise AssertionError(
                f"e2e requires a clean Vaultwarden vault but found {len(before_items)} "
                "items. Recreate the server (e.g. `docker compose -f tests/"
                "docker-compose.yml down -v`) before running."
            )

        snapshot_path = tmp / "snapshot.kdbx"
        _create_keepass_snapshot(snapshot_path, kp_password)
        logger.info("Created KeePass snapshot")

        logger.info("Running kp2bw migration (first pass)")
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        s1 = _capture_vault(env, session, download_dir=downloads / "p1")
        logger.info(f"First pass migrated {len(s1['items'])} items")

        logger.info("Running kp2bw migration (idempotency pass)")
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        s2 = _capture_vault(env, session, download_dir=downloads / "p2")

        # The headline reproducibility proof: a second migration with an
        # unchanged source must produce a byte-identical normalized vault.
        _assert_snapshots_equal(s1, s2, label="idempotency (pass 1 vs pass 2)")

        if _golden_enabled():
            assert_matches_golden(s2, GOLDEN_INITIAL)
            logger.info("Initial vault snapshot matches golden")

        # Sharp, named behavioral checks over the comprehensive seed.
        _assert_comprehensive_seed(s2)

        # --- Existing #11 contract checks (kept verbatim in spirit) ----------
        folders = _bw_json(env, "list", "folders", "--session", session)
        if not any(folder.get("name") == "Internet" for folder in folders):
            raise AssertionError("Expected folder 'Internet' not found in Bitwarden")

        example = _item_by_name(s2, "Example")
        example_login = _login(example)
        if (
            example_login["username"] != "demo-user"
            or example_login["password"] != "demo-pass"
        ):
            raise AssertionError("Example item credentials were not migrated correctly")
        if not any(
            uri["uri"] == "https://example.com" for uri in example_login["uris"]
        ):
            raise AssertionError("Example item URL was not migrated correctly")
        if _field(example, "api_token")["value"] != "abc123":
            raise AssertionError("Expected custom field api_token=abc123 not found")
        example_totp = example_login["totp"] or ""
        if not example_totp.startswith("otpauth://totp/"):
            raise AssertionError(
                f"Expected an otpauth TOTP URI on Example, got {example_totp!r}"
            )
        if (
            "secret=JBSWY3DPEHPK3PXP" not in example_totp
            or "period=60" not in example_totp
        ):
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

        root_login = _login(_item_by_name(s2, "Root Entry"))
        if (
            root_login["username"] != "root-user"
            or root_login["password"] != "root-pass"
        ):
            raise AssertionError("Root Entry credentials were not migrated correctly")

        # --- Update pass: edit KeePass, re-run, verify the changes sync ------
        logger.info("Editing KeePass snapshot and running update pass")
        _update_keepass_snapshot(snapshot_path, kp_password)
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        s3 = _capture_vault(env, session, download_dir=downloads / "p3")

        if _golden_enabled():
            assert_matches_golden(s3, GOLDEN_AFTER_UPDATE)
            logger.info("Post-update vault snapshot matches golden")

        # Existing "Example" entry must be updated in place, not duplicated.
        example = _item_by_name(s3, "Example")
        if example["notes"] != "updated recovery keys":
            raise AssertionError(
                f"Edited notes were not synced to Bitwarden: {example['notes']!r}"
            )
        if _login(example)["password"] != "demo-pass-v2":
            raise AssertionError("Edited password was not synced to Bitwarden")

        # The long-note entry must store its note as a notes.txt attachment.
        big = _item_by_name(s3, "Big Note")
        if not any(att["fileName"] == "notes.txt" for att in big["attachments"]):
            raise AssertionError(
                f"Long note was not uploaded as a notes.txt attachment: {big['attachments']}"
            )
        if len(big["notes"] or "") > 10 * 1000:
            raise AssertionError("Long note should be offloaded to the attachment")

        # Re-locate Big Note's server id for raw attachment-content checks.
        items = _bw_json(env, "list", "items", "--session", session)
        big_matches = [i for i in items if i.get("name") == "Big Note"]
        if len(big_matches) != 1:
            raise AssertionError(f"Expected one 'Big Note', found {len(big_matches)}")
        big_id = str(big_matches[0]["id"])
        original_attachment = _get_attachment_text(env, session, big_id, "notes.txt")
        if original_attachment != LONG_NOTE:
            raise AssertionError(
                "notes.txt attachment content does not match the original long note"
            )

        # --- Attachment refresh: edit the long note (same filename) and re-run.
        # The notes.txt attachment must be replaced with the new content and the
        # stale copy removed -- not left as a duplicate (content-aware sync, #11).
        logger.info("Editing Big Note's long note and running attachment-refresh pass")
        _edit_big_note_snapshot(snapshot_path, kp_password, LONG_NOTE_V2)
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)

        items = _bw_json(env, "list", "items", "--session", session)
        big_after_refresh = [i for i in items if i.get("name") == "Big Note"]
        if len(big_after_refresh) != 1 or str(big_after_refresh[0]["id"]) != big_id:
            raise AssertionError(
                f"Attachment-refresh re-run must not duplicate 'Big Note': {big_after_refresh}"
            )
        big_full = parse_object(
            _run(["bw", "get", "item", big_id, "--session", session], env=env)
        )
        raw_big_atts = big_full.get("attachments")
        big_att_list: list[JsonValue] = (
            raw_big_atts if isinstance(raw_big_atts, list) else []
        )
        notes_copies = [
            att for att in big_att_list if as_object(att).get("fileName") == "notes.txt"
        ]
        if len(notes_copies) != 1:
            raise AssertionError(
                f"Refreshed attachment must replace, not duplicate: {notes_copies}"
            )
        refreshed_attachment = _get_attachment_text(env, session, big_id, "notes.txt")
        if refreshed_attachment != LONG_NOTE_V2:
            raise AssertionError(
                "notes.txt attachment was not refreshed with the edited long note"
            )

        # Final idempotent re-run (no edits) must change nothing.
        s_refresh = _capture_vault(env, session, download_dir=downloads / "p4a")
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        s_final = _capture_vault(env, session, download_dir=downloads / "p4b")
        _assert_snapshots_equal(
            s_refresh, s_final, label="idempotency (refreshed state)"
        )

    print("vaultwarden end-to-end integration test passed")


if __name__ == "__main__":
    main()
