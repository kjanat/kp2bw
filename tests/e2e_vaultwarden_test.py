import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from pykeepass import PyKeePass, create_database

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

    _ = kp.add_entry(
        kp.root_group,
        "Root Entry",
        "root-user",
        "root-pass",
        notes="root note",
    )

    kp.save()


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
        _ = _run(
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
        logger.info("First migration pass complete")

        logger.info("Running kp2bw migration (idempotency pass)")
        _ = _run(
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

    print("vaultwarden end-to-end integration test passed")


if __name__ == "__main__":
    main()
