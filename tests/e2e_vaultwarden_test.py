import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import cast

from pykeepass import Entry, PyKeePass, create_database

logger = logging.getLogger("e2e")

SENSITIVE_ARG_FLAGS = {
    "--bitwarden-password",
    "--keepass-password",
    "--passwordenv",
    "--session",
}


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


def _bw_json(env: dict[str, str], *args: str) -> list[dict[str, object]]:
    output = _run(["bw", *args], env=env)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Expected JSON output from bw command {' '.join(args)}, got:\n{output}"
        ) from exc


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


def _create_keepass_snapshot(path: Path, password: str) -> None:
    create_database(str(path), password=password)
    kp = PyKeePass(str(path), password=password)

    internet = kp.add_group(kp.root_group, "Internet")
    example = kp.add_entry(
        internet,
        "Example",
        "demo-user",
        "demo-pass",
        url="https://example.com",
        notes="seed note",
    )
    example.set_custom_property("api_token", "abc123")
    # KeePassXC-native TOTP with a non-default period: must migrate to login.totp
    # as an otpauth:// URI (not a bare secret) and not leak into custom fields.
    example.set_custom_property("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")
    example.set_custom_property("TimeOtp-Period", "60")

    _ = kp.add_entry(
        kp.root_group,
        "Root Entry",
        "root-user",
        "root-pass",
        notes="root note",
    )

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

        snapshot_path = tmp / "snapshot.kdbx"
        _create_keepass_snapshot(snapshot_path, kp_password)
        logger.info("Created KeePass snapshot")

        logger.info("Running kp2bw migration (first pass)")
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        logger.info("First migration pass complete")

        logger.info("Running kp2bw migration (idempotency pass)")
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        logger.info("Second migration pass complete")

        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)

        folders = _bw_json(env, "list", "folders", "--session", session)
        if not any(folder.get("name") == "Internet" for folder in folders):
            raise AssertionError("Expected folder 'Internet' not found in Bitwarden")

        items = _bw_json(env, "list", "items", "--session", session)

        expected_names = {"Example", "Root Entry"}
        matching = [item for item in items if item.get("name") in expected_names]

        if len(matching) != 2:
            raise AssertionError(
                f"Expected exactly 2 migrated items, found {len(matching)} ({matching})"
            )

        name_counts = {name: 0 for name in expected_names}
        for item in matching:
            name = str(item.get("name"))
            name_counts[name] += 1
        if any(count != 1 for count in name_counts.values()):
            raise AssertionError(
                f"Expected idempotent import, got name counts: {name_counts}"
            )

        example = next(item for item in matching if item.get("name") == "Example")
        root_entry = next(item for item in matching if item.get("name") == "Root Entry")

        example_id = str(example["id"])
        root_entry_id = str(root_entry["id"])

        example_full = json.loads(
            _run(["bw", "get", "item", example_id, "--session", session], env=env)
        )
        root_entry_full = json.loads(
            _run(["bw", "get", "item", root_entry_id, "--session", session], env=env)
        )

        example_login = example_full["login"]
        if (
            example_login["username"] != "demo-user"
            or example_login["password"] != "demo-pass"
        ):
            raise AssertionError("Example item credentials were not migrated correctly")

        uris = example_login.get("uris", [])
        if not any(uri.get("uri") == "https://example.com" for uri in uris):
            raise AssertionError("Example item URL was not migrated correctly")

        fields = example_full.get("fields", [])
        if not any(
            field.get("name") == "api_token" and field.get("value") == "abc123"
            for field in fields
        ):
            raise AssertionError("Expected custom field api_token=abc123 not found")

        # KeePassXC-native TOTP (non-default period) must land in login.totp as an
        # otpauth:// URI carrying the secret + period, never as a bare secret.
        example_totp = example_login.get("totp")
        if not example_totp or not str(example_totp).startswith("otpauth://totp/"):
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

        # The consumed TimeOtp-* fields must NOT linger as custom fields (no leak).
        leaked = [
            field.get("name")
            for field in fields
            if field.get("name") in {"TimeOtp-Secret-Base32", "TimeOtp-Period"}
        ]
        if leaked:
            raise AssertionError(
                f"TOTP fields leaked into custom fields instead of login.totp: {leaked}"
            )

        root_login = root_entry_full["login"]
        if (
            root_login["username"] != "root-user"
            or root_login["password"] != "root-pass"
        ):
            raise AssertionError("Root Entry credentials were not migrated correctly")

        if len(items) < len(before_items) + 2:
            raise AssertionError(
                "Expected at least two new items after migration, but item count did not grow"
            )

        # --- Update pass: edit KeePass, re-run, and verify the changes sync ---
        logger.info("Editing KeePass snapshot and running update pass")
        _update_keepass_snapshot(snapshot_path, kp_password)
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        logger.info("Update migration pass complete")

        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        items = _bw_json(env, "list", "items", "--session", session)

        # Existing "Example" entry must be updated in place, not duplicated.
        examples = [i for i in items if i.get("name") == "Example"]
        if len(examples) != 1:
            raise AssertionError(
                f"Update must not duplicate entries; found {len(examples)} 'Example'"
            )

        example_full = json.loads(
            _run(
                ["bw", "get", "item", str(examples[0]["id"]), "--session", session],
                env=env,
            )
        )
        if example_full.get("notes") != "updated recovery keys":
            raise AssertionError(
                f"Edited notes were not synced to Bitwarden: {example_full.get('notes')!r}"
            )
        if example_full["login"]["password"] != "demo-pass-v2":
            raise AssertionError("Edited password was not synced to Bitwarden")

        # The long-note entry must store its note as a notes.txt attachment.
        big_notes = [i for i in items if i.get("name") == "Big Note"]
        if len(big_notes) != 1:
            raise AssertionError(
                f"Expected exactly one 'Big Note' entry, found {len(big_notes)}"
            )
        big_full = json.loads(
            _run(
                ["bw", "get", "item", str(big_notes[0]["id"]), "--session", session],
                env=env,
            )
        )
        attachments = big_full.get("attachments", [])
        if not any(a.get("fileName") == "notes.txt" for a in attachments):
            raise AssertionError(
                f"Long note was not uploaded as a notes.txt attachment: {attachments}"
            )
        if len(big_full.get("notes") or "") > 10 * 1000:
            raise AssertionError("Long note should be offloaded to the attachment")

        big_id = str(big_notes[0]["id"])
        # The attachment must carry the original long note verbatim.
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

        # The refresh re-run must update in place, not spawn a second item:
        # re-list by name and confirm there's still exactly one 'Big Note' with
        # the same id (otherwise the attachment checks below could pass on the
        # original item while a duplicate sinks idempotency). `items` is reused
        # for the final idempotency check.
        items = _bw_json(env, "list", "items", "--session", session)
        big_after_refresh = [i for i in items if i.get("name") == "Big Note"]
        if len(big_after_refresh) != 1 or str(big_after_refresh[0]["id"]) != big_id:
            raise AssertionError(
                f"Attachment-refresh re-run must not duplicate 'Big Note': "
                f"{big_after_refresh}"
            )

        big_full = json.loads(
            _run(["bw", "get", "item", big_id, "--session", session], env=env)
        )
        notes_attachments = [
            a
            for a in big_full.get("attachments", [])
            if a.get("fileName") == "notes.txt"
        ]
        if len(notes_attachments) != 1:
            raise AssertionError(
                f"Refreshed attachment must replace, not duplicate: {notes_attachments}"
            )
        refreshed_attachment = _get_attachment_text(env, session, big_id, "notes.txt")
        if refreshed_attachment != LONG_NOTE_V2:
            raise AssertionError(
                "notes.txt attachment was not refreshed with the edited long note"
            )

        # Re-running with no further edits must be idempotent (no duplicates).
        _ = _run_migration(snapshot_path, kp_password, bw_password, env)
        # kp2bw's `bw serve` rotates the shared CLI session, so re-acquire one
        # before querying again (a stale token returns an empty item list).
        session = _get_session(env, bw_password)
        _ = _run(["bw", "sync", "--session", session], env=env)
        items_after = _bw_json(env, "list", "items", "--session", session)
        if len([i for i in items_after if i.get("name") == "Example"]) != 1:
            raise AssertionError("Idempotent re-run duplicated the 'Example' entry")
        if len(items_after) != len(items):
            raise AssertionError(
                f"Idempotent re-run changed item count: {len(items)} -> {len(items_after)}"
            )

        # An unchanged attachment must not be re-uploaded or duplicated either:
        # content-aware reconciliation has to see identical bytes and skip.
        big_after = json.loads(
            _run(["bw", "get", "item", big_id, "--session", session], env=env)
        )
        notes_after = [
            a
            for a in big_after.get("attachments", [])
            if a.get("fileName") == "notes.txt"
        ]
        if len(notes_after) != 1:
            raise AssertionError(
                f"Idempotent re-run changed notes.txt copies: {len(notes_after)}"
            )

    print("vaultwarden end-to-end integration test passed")


if __name__ == "__main__":
    main()
