import json
import os
import subprocess
import tempfile
from pathlib import Path

from pykeepass import PyKeePass, create_database


def _run(command: list[str], *, env: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def _bw_json(env: dict[str, str], *args: str) -> list[dict[str, object]]:
    output = _run(["bw", *args], env=env)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"Expected JSON output from bw command {' '.join(args)}, got:\n{output}"
        ) from exc


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


def main() -> None:
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

        _ = _run(["bw", "config", "server", server_url], env=env)
        _ = _run(["bw", "login", bw_email, bw_password, "--nointeraction"], env=env)

        initial_session = _run(["bw", "unlock", bw_password, "--raw"], env=env)
        before_items = _bw_json(env, "list", "items", "--session", initial_session)

        snapshot_path = tmp / "snapshot.kdbx"
        _create_keepass_snapshot(snapshot_path, kp_password)

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
            ],
            env=env,
        )

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
            ],
            env=env,
        )

        session = _run(["bw", "unlock", bw_password, "--raw"], env=env)
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
