"""Exercise the production image, including state persistence and termination."""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from pykeepass import create_database


def main() -> None:
    image = os.environ["KP2BW_CONTAINER_IMAGE"]
    expected_version = os.environ["KP2BW_CONTAINER_VERSION"]
    expected_bw = os.environ["KP2BW_CONTAINER_BW_VERSION"]
    root = Path(__file__).resolve().parents[1]
    volume = f"kp2bw-image-test-{uuid4().hex}"
    stopped = f"{volume}-stop"
    env = os.environ.copy()
    env.update(
        KP2BW_KEEPASS_PASSWORD="synthetic",
        KP2BW_BITWARDEN_PASSWORD="TestMasterPassword123!",
        BW_PASSWORD="TestMasterPassword123!",
        KP2BW_YES="true",
        BW_NOINTERACTION="true",
    )

    def run(
        args: list[str],
        *,
        allowed: tuple[int, ...] = (0,),
        timeout: int = 180,
        stderr: bool = False,
    ) -> str:
        result = subprocess.run(
            args,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode not in allowed:
            # Never print login/unlock output or credential-bearing command lines.
            raise AssertionError(f"Container test command exited {result.returncode}")
        return (result.stderr if stderr else result.stdout).strip()

    run(["docker", "volume", "create", volume])
    try:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            source.chmod(0o755)
            keyfile = source / "key.key"
            keyfile.write_bytes(bytes(range(32)))
            db = create_database(
                source / "vault.kdbx", password="synthetic", keyfile=str(keyfile)
            )
            entry = db.add_entry(
                db.root_group, "Container round trip", "user", "password"
            )
            entry.notes = "production image"
            entry.add_attachment(db.add_binary(b"container attachment"), "file.bin")
            db.save()
            for path in source.iterdir():
                path.chmod(0o644)
            base = [
                "docker",
                "run",
                "--rm",
                "--network",
                "host",
                "--mount",
                f"type=volume,src={volume},dst=/data",
                "--mount",
                f"type=bind,src={source},dst=/source,readonly",
                "--mount",
                f"type=bind,src={root / 'tests/fixtures/vaultwarden-certs/cert.pem'},dst=/cert.pem,readonly",
                "--env",
                "NODE_EXTRA_CA_CERTS=/cert.pem",
                "--env",
                "KP2BW_KEEPASS_PASSWORD",
                "--env",
                "KP2BW_BITWARDEN_PASSWORD",
                "--env",
                "BW_PASSWORD",
                "--env",
                "KP2BW_YES",
                "--env",
                "BW_NOINTERACTION",
            ]
            assert "Import KeePass" in run([*base, image, "--help"])
            assert expected_version in run([*base, image, "--version"])
            assert run([*base, "--entrypoint", "bw", image, "--version"]) == expected_bw
            assert run([*base, "--entrypoint", "id", image, "-u"]) == "10001"
            run([
                *base,
                "--entrypoint",
                "bw",
                image,
                "config",
                "server",
                os.environ.get("BW_SERVER_URL", "https://localhost:18443"),
            ])
            run(
                [
                    *base,
                    "--entrypoint",
                    "bw",
                    image,
                    "login",
                    "integration@example.com",
                    "--passwordenv",
                    "BW_PASSWORD",
                    "--raw",
                ],
                allowed=(0, 1),
            )
            # An already authenticated CLI may report a one-off key backfill
            # error while unlocking; a fresh invocation must still retain login.
            status = json.loads(run([*base, "--entrypoint", "bw", image, "status"]))
            assert status["status"] != "unauthenticated", (
                "Login did not survive container replacement"
            )
            doctor = run([*base, image, "--doctor"], stderr=True)
            assert expected_bw in doctor
            args = [
                "/source/vault.kdbx",
                "--keepass-keyfile",
                "/source/key.key",
                "--no-metadata",
                "--no-path-to-name",
            ]
            run([*base, image, *args])
            verify = """
import hashlib, json, os
from kp2bw.bw_serve import BitwardenServeClient
with BitwardenServeClient(os.environ["KP2BW_BITWARDEN_PASSWORD"]) as bw:
    matches = [item for item in bw.list_items() if any(f.get("name") == "KP2BW_ID" and f.get("value") == os.environ["SOURCE_UUID"] for f in item.get("fields") or [])]
    assert len(matches) == 1
    item = bw.get_item(matches[0]["id"])
    assert item["name"] == "Container round trip"
    assert item["notes"] == "production image"
    assert item["login"]["username"] == "user"
    assert item["login"]["password"] == "password"
    attachments = item.get("attachments") or []
    assert len(attachments) == 1
    data = bw.get_attachment(item["id"], attachments[0]["id"])
    print(json.dumps([item["id"], item["revisionDate"], attachments[0]["id"], hashlib.sha256(data).hexdigest()]))
"""
            verify_args = [
                *base,
                "--env",
                f"SOURCE_UUID={entry.uuid.hex.upper()}",
                "--entrypoint",
                "python",
                image,
                "-c",
                verify,
            ]
            before = run(verify_args)
            assert (
                json.loads(before)[3]
                == hashlib.sha256(b"container attachment").hexdigest()
            )
            run([*base, image, *args])
            assert run(verify_args) == before, (
                "Second container changed item revision or attachment identity"
            )
            # Start the actual entrypoint and stop it once its child serve
            # process exists. Inspect only a boolean, never /proc command data.
            detached = [arg for arg in base if arg != "--rm"]
            run([*detached, "--detach", "--name", stopped, image, *args])
            probe = """
from pathlib import Path
print(any(b"serve" in p.read_bytes().split(b"\\0") for p in Path("/proc").glob("[0-9]*/cmdline") if p.exists()))
"""
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if (
                    run(
                        ["docker", "exec", stopped, "python", "-c", probe],
                        allowed=(0, 1),
                    )
                    == "True"
                ):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(
                    "No child serve process appeared before termination test"
                )
            run(["docker", "stop", "--timeout", "10", stopped])
            state = json.loads(
                run(["docker", "inspect", "--format", "{{json .State}}", stopped])
            )
            assert not state["Running"] and state["ExitCode"] == 143, state
            # A subsequent invocation can unlock the same profile and complete.
            run([*base, image, *args])
            assert run(verify_args) == before
    finally:
        run(["docker", "rm", "--force", stopped], allowed=(0, 1))
        run(["docker", "volume", "rm", "--force", volume])
    print(
        "production image: non-root, login persistence, migration, idempotency and SIGTERM passed"
    )


if __name__ == "__main__":
    main()
