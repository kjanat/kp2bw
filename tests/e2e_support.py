import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from unittest.mock import patch

from scope_fixture import SCOPE_COLLECTION, create_scope_organization
from snapshot import objects, opt_str

from kp2bw.bw_serve import BitwardenServeClient, resolve_cli_command
from kp2bw.bw_types import BwItemResponse
from kp2bw.exceptions import BitwardenHttpError

logger = logging.getLogger("e2e")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CERT = REPO_ROOT / "tests/fixtures/vaultwarden-certs/cert.pem"

SENSITIVE_ARG_FLAGS = {
    "--bitwarden-password",
    "--keepass-password",
    "--passwordenv",
    "--session",
}


def collect_sensitive_values(command: list[str]) -> tuple[str, ...]:
    """Collect sensitive CLI values from command arguments."""
    values: list[str] = []
    for i, arg in enumerate(command[:-1]):
        if arg in SENSITIVE_ARG_FLAGS:
            values.append(command[i + 1])
    return tuple(values)


def redact_output(output: str, *, command: list[str], secrets: tuple[str, ...]) -> str:
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


def as_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run(
    command: list[str],
    *,
    env: Mapping[str, str],
    timeout: float = 300,
    expected: int = 0,
    tolerated_error: str | None = None,
    secrets: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    secrets = (*collect_sensitive_values(command), *secrets)
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
            env=dict(env),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = redact_output(as_text(exc.stdout), command=command, secrets=secrets)
        stderr = redact_output(as_text(exc.stderr), command=command, secrets=secrets)
        raise AssertionError(
            f"Command timed out after {timeout}s: {safe_cmd}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from exc
    if (
        result.returncode != expected
        and tolerated_error is not None
        and tolerated_error in result.stderr
    ):
        logger.warning(f"  exit {result.returncode} with {tolerated_error}; continuing")
        return result
    if result.returncode != expected:
        stdout = redact_output(result.stdout, command=command, secrets=secrets)
        stderr = redact_output(result.stderr, command=command, secrets=secrets)
        raise AssertionError(
            f"Command returned {result.returncode}, expected {expected}: {safe_cmd}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return result


@dataclass(frozen=True)
class Account:
    server: str
    cert: Path
    email: str
    password: str
    profile: Path | None
    container: str | None

    @classmethod
    def from_env(cls) -> Self:
        profile = os.environ.get("KP2BW_E2E_BW_PROFILE")
        cert = Path(os.environ.get("BW_CERT_PATH", str(DEFAULT_CERT)))
        if not cert.exists():
            raise AssertionError(f"Missing cert file: {cert}")
        return cls(
            server=os.environ.get("BW_SERVER_URL", "https://localhost:18443"),
            cert=cert,
            email=os.environ.get("BW_TEST_EMAIL", "integration@example.com"),
            password=os.environ.get("BW_TEST_PASSWORD", "TestMasterPassword123!"),
            profile=Path(profile) if profile else None,
            container=os.environ.get("KP2BW_E2E_VAULTWARDEN_CONTAINER") or None,
        )


class SharedClient(BitwardenServeClient):
    written = False

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: dict[str, str] | None = None,
        idempotent: bool | None = None,
    ) -> dict[str, Any]:
        if method != "GET" and path not in {"/sync", "/unlock"}:
            self.written = True
        response = super().request(
            method, path, json_body=json_body, params=params, idempotent=idempotent
        )
        if path == "/sync" and params == {"force": "true"}:
            self.written = False
        return response

    def upload_attachments(
        self,
        items: list[tuple[str, list[tuple[str, bytes]]]],
        *,
        max_concurrency: int = 4,
    ) -> list[tuple[str, str]]:
        self.written = True
        return super().upload_attachments(items, max_concurrency=max_concurrency)


class Vault:
    account: Account
    tmp: Path
    env: dict[str, str]
    client: SharedClient

    def __init__(self, account: Account, tmp: Path) -> None:
        self.account = account
        self.tmp = tmp
        self.profile = account.profile or tmp / "profile"
        self.env = {
            "BITWARDENCLI_APPDATA_DIR": str(self.profile),
            "VW_APPDATA_DIR": str(self.profile),
            "NODE_EXTRA_CA_CERTS": str(account.cert),
            "BW_NOINTERACTION": "true",
            "BW_SERVER_URL": account.server,
            "BW_TEST_EMAIL": account.email,
            "BW_TEST_PASSWORD": account.password,
        }
        self.stack = ExitStack()

    @property
    def password(self) -> str:
        return self.account.password

    def __enter__(self) -> Self:
        self.stack.enter_context(patch.dict(os.environ, self.env))
        try:
            self.authenticate()
            self.client = SharedClient(self.password)
            self.stack.callback(self.client.close)
        except BaseException:
            self.stack.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stack.close()

    def cli_command(self, *args: str) -> list[str]:
        command, _ = resolve_cli_command()
        return [*command, *args]

    def authenticate(self) -> None:
        env = {**os.environ, "BW_PASSWORD": self.password}
        if self.account.profile is not None:
            status = json.loads(run(self.cli_command("status"), env=env).stdout)
            if status.get("serverUrl", "").rstrip("/") != self.account.server.rstrip(
                "/"
            ):
                raise AssertionError("Saved CLI profile targets a different server")
            if status.get("userEmail", "").casefold() != self.account.email.casefold():
                raise AssertionError("Saved CLI profile belongs to another account")
            return
        self.profile.mkdir(parents=True, exist_ok=True)
        run(self.cli_command("config", "server", self.account.server), env=env)
        # bw 2026.9.0+ logs in, then fails with KeyIdBackfillError against
        # Vaultwarden up to 1.37.3. https://github.com/bitwarden/clients/issues/23937
        run(
            self.cli_command(
                "login", self.account.email, "--passwordenv", "BW_PASSWORD", "--raw"
            ),
            env=env,
            tolerated_error="KeyIdBackfillError",
        )

    def detached_env(
        self, extra: Mapping[str, str] | None = None, unset: Collection[str] = ()
    ) -> dict[str, str]:
        profile = Path(tempfile.mkdtemp(dir=self.tmp)) / "profile"
        shutil.copytree(self.profile, profile)
        env = {
            **os.environ,
            "BITWARDENCLI_APPDATA_DIR": str(profile),
            "VW_APPDATA_DIR": str(profile),
            **(extra or {}),
        }
        for name in unset:
            env.pop(name, None)
        return env

    def kp2bw(
        self,
        *args: str,
        expected: int = 0,
        env: Mapping[str, str] | None = None,
        unset: Collection[str] = (),
    ) -> subprocess.CompletedProcess[str]:
        result = run(
            ["uv", "run", "kp2bw", *args],
            env=self.detached_env(env, unset),
            expected=expected,
            secrets=(self.password,),
        )
        self.sync()
        return result

    def migrate_args(
        self,
        source: Path,
        kp_password: str,
        *,
        metadata: bool = False,
        extra_args: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        return (
            str(source),
            "--keepass-password",
            kp_password,
            "--bitwarden-password",
            self.password,
            "--path-to-name-skip",
            "999",
            "--metadata" if metadata else "--no-metadata",
            "-y",
            "-v",
            *extra_args,
        )

    def migrate(
        self,
        source: Path,
        kp_password: str,
        *,
        metadata: bool = False,
        extra_args: tuple[str, ...] = (),
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.kp2bw(
            *self.migrate_args(
                source, kp_password, metadata=metadata, extra_args=extra_args
            ),
            env=env,
        )

    def kp2bw_parallel(
        self, runs: Sequence[tuple[Sequence[str], Mapping[str, str] | None]]
    ) -> list[subprocess.CompletedProcess[str]]:
        commands = [
            (["uv", "run", "kp2bw", *args], self.detached_env(env))
            for args, env in runs
        ]
        with ThreadPoolExecutor(len(commands)) as pool:
            futures = [
                pool.submit(run, command, env=env, secrets=(self.password,))
                for command, env in commands
            ]
            results = [future.result() for future in futures]
        self.sync()
        return results

    def child(self, script: Path, *args: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, str(script), *args],
            env=self.detached_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def sync(self) -> None:
        self.client.sync(force=True)
        self.client.written = False

    def fresh(self) -> SharedClient:
        # The official CLI can answer reads from its cache before a PUT lands there.
        if self.client.written:
            self.sync()
        return self.client

    def organization(self) -> str:
        organization = create_scope_organization(
            self.account.server,
            self.account.cert,
            self.account.email,
            self.account.password,
        )
        # The official CLI publishes a forced sync to its cache after responding.
        for _ in range(3):
            self.sync()
            for attempt in range(6):
                if SCOPE_COLLECTION in self.visible_collections(organization):
                    return organization
                time.sleep(min(0.1 * 2**attempt, 1.0))
        raise AssertionError("The new organization's collection never became visible")

    def visible_collections(self, organization: str) -> dict[str, str]:
        try:
            return self.collections(organization)
        except BitwardenHttpError as error:
            if error.status_code != 400 or "Organization not found" not in str(error):
                raise
            return {}

    def collections(self, organization: str) -> dict[str, str]:
        response = self.fresh().request(
            "GET",
            "/list/object/org-collections",
            params={"organizationId": organization},
        )
        result: dict[str, str] = {}
        for row in objects(response, "data"):
            name, identifier = opt_str(row, "name"), opt_str(row, "id")
            if name is None or identifier is None or name in result:
                raise AssertionError("Organization collections are ambiguous")
            result[name] = identifier
        return result

    def find(self, source_uuid: str) -> BwItemResponse | None:
        bw = self.fresh()
        bw.refresh_dedup_index()
        listed = bw.get_item_by_uuid(source_uuid)
        return None if listed is None else bw.get_item(listed["id"])

    def item(self, source_uuid: str) -> BwItemResponse:
        found = self.find(source_uuid)
        if found is None:
            raise AssertionError(f"No item carries source UUID {source_uuid}")
        return found

    def items(self) -> list[BwItemResponse]:
        return self.fresh().list_items()

    def named(self, *names: str) -> dict[str, BwItemResponse]:
        items = self.items()
        result: dict[str, BwItemResponse] = {}
        for name in names:
            matches = [item for item in items if item.get("name") == name]
            if len(matches) != 1:
                raise AssertionError(
                    f"expected one item named {name!r}, found {len(matches)}"
                )
            result[name] = matches[0]
        return result

    def delete(self, *item_ids: str) -> None:
        for item_id in item_ids:
            self.client.request("DELETE", f"/object/item/{item_id}")

    def delete_sources(
        self, source_uuids: Collection[str], names: Collection[str]
    ) -> None:
        self.delete(
            *(
                item["id"]
                for item in self.items()
                if item.get("name") in names
                and any(
                    field["name"] == "KP2BW_ID" and field["value"] in source_uuids
                    for field in item.get("fields") or []
                )
            )
        )

    def attachment(self, item_id: str, file_name: str) -> bytes:
        bw = self.fresh()
        matches = [
            attachment["id"]
            for attachment in bw.get_item(item_id).get("attachments") or []
            if attachment["fileName"] == file_name
        ]
        if len(matches) != 1:
            raise AssertionError(f"expected one attachment {file_name!r}")
        return bw.get_attachment(item_id, matches[0])


def vault_main(run_test: Callable[[Vault], None]) -> None:
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s: %(message)s", level=logging.INFO
    )
    with (
        tempfile.TemporaryDirectory() as directory,
        Vault(Account.from_env(), Path(directory)) as vault,
    ):
        run_test(vault)
