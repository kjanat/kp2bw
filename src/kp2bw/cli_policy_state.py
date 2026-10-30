"""Read policy metadata from the exact CLI profile serving the active vault.

No tokens, encryption keys or cipher contents are returned or logged. These
adapters recognize explicit storage shapes and reject missing or stale data.
"""

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from .exceptions import BitwardenClientError
from .ssh_policy import PolicyObject


@dataclass(frozen=True)
class CliPolicyState:
    kind: Literal["bitwarden", "vaultwarden"]
    api_url: str
    organizations: tuple[PolicyObject, ...]
    policies: tuple[PolicyObject, ...]
    premium: bool | None = None


def policy_premium(*values: object) -> bool | None:
    if any(value is True for value in values):
        return True
    return False if all(value is False for value in values) else None


def policy_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BitwardenClientError("Cannot verify SSH policy: unsupported CLI metadata")
    return cast(dict[str, object], value)


def objects(value: object, *, record: bool = False) -> tuple[PolicyObject, ...]:
    if record:
        return tuple(policy_object(item) for item in policy_object(value).values())
    if not isinstance(value, list):
        raise BitwardenClientError(
            "Cannot verify SSH policy: missing policy or membership list"
        )
    return tuple(policy_object(item) for item in cast(list[object], value))


def url(value: object) -> str:
    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        raise BitwardenClientError("Cannot verify SSH policy: missing server address")
    return value.rstrip("/")


def timestamp(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                return parsed
        except ValueError:
            pass
    raise BitwardenClientError(
        "Cannot verify SSH policy: missing synchronization timestamp"
    )


def parse_policy_state(
    state: Mapping[str, object],
    status: Mapping[str, object],
    *,
    synced_after: datetime,
) -> CliPolicyState:
    """Bind cached policy data to an unlocked account and a completed fresh sync."""
    user_id = status.get("userId")
    if (
        not isinstance(user_id, str)
        or not user_id
        or status.get("status") != "unlocked"
    ):
        raise BitwardenClientError("Cannot verify SSH policy: no unlocked CLI account")
    live_sync = timestamp(status.get("lastSync"))
    # JavaScript Date records milliseconds; Python's clock includes microseconds.
    # A sync starting within the same millisecond must not look older solely
    # because the CLI truncated that fractional precision.
    earliest_sync = synced_after.replace(
        microsecond=(synced_after.microsecond // 1000) * 1000
    )
    if live_sync < earliest_sync:
        raise BitwardenClientError(
            "Cannot verify SSH policy: the CLI did not finish a fresh sync"
        )
    if state.get("global_account_activeAccountId") == user_id:
        prefix = f"user_{user_id}_"
        if timestamp(state.get(prefix + "sync_lastSync")) != live_sync:
            raise BitwardenClientError("Cannot verify SSH policy: stale CLI profile")
        environment = policy_object(state.get(prefix + "environment_environment"))
        urls = policy_object(environment.get("urls"))
        base = urls.get("base")
        if base:
            if url(base) != url(status.get("serverUrl")):
                raise BitwardenClientError(
                    "Cannot verify SSH policy: CLI server does not match"
                )
            api = url(urls.get("api")) if urls.get("api") else url(base) + "/api"
        else:
            region = environment.get("region")
            if region not in ("US", "EU"):
                raise BitwardenClientError(
                    "Cannot verify SSH policy: unknown CLI server region"
                )
            api = (
                "https://api.bitwarden.eu"
                if region == "EU"
                else "https://api.bitwarden.com"
            )
            suffix = "eu" if region == "EU" else "com"
            if status.get("serverUrl") not in (
                None,
                f"https://vault.bitwarden.{suffix}",
                f"https://bitwarden.{suffix}",
            ):
                raise BitwardenClientError(
                    "Cannot verify SSH policy: CLI server does not match"
                )
            if urls.get("api"):
                api = url(urls["api"])
        organizations = objects(
            state.get(prefix + "organizations_organizations"), record=True
        )
        policies = objects(state.get(prefix + "policies_policies"), record=True)
        policies += objects(state.get(prefix + "policies_policiesNew"), record=True)
        billing = state.get(prefix + "billing_accountProfile")
        premium = None
        if isinstance(billing, dict):
            profile = cast(dict[str, object], billing)
            premium = policy_premium(
                profile.get("hasPremiumPersonally"),
                profile.get("hasPremiumFromAnyOrganization"),
            )
        return CliPolicyState("bitwarden", api, organizations, policies, premium)
    if state.get("version") == 1:
        vault = policy_object(state.get("vault"))
        profile = policy_object(vault.get("profile"))
        if profile.get("id") != user_id or url(state.get("server")) != url(
            status.get("serverUrl")
        ):
            raise BitwardenClientError(
                "Cannot verify SSH policy: CLI account or server does not match"
            )
        if timestamp(state.get("lastSync")) != live_sync:
            raise BitwardenClientError("Cannot verify SSH policy: stale CLI profile")
        api = url(state.get("server")) + "/api"
        services = state.get("services")
        if services is not None:
            configured_api = policy_object(services).get("api")
            if configured_api:
                api = url(configured_api)
        organizations = objects(profile.get("organizations"))
        policies = objects(vault.get("policies"))
        policies += objects(vault.get("policiesNew", []))
        return CliPolicyState(
            "vaultwarden",
            api,
            organizations,
            policies,
            policy_premium(
                profile.get("premium"), profile.get("premiumFromOrganization", False)
            ),
        )
    raise BitwardenClientError("Cannot verify SSH policy: unrecognized CLI profile")


def profile_candidates() -> tuple[Path, ...]:
    """Mirror the two CLIs' documented environment and platform defaults."""
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    if explicit := os.environ.get("BITWARDENCLI_APPDATA_DIR"):
        bw = Path(explicit)
    elif sys.platform == "darwin":
        bw = Path.home() / "Library/Application Support/Bitwarden CLI"
    elif sys.platform == "win32":
        bw = Path(os.environ.get("APPDATA", "")) / "Bitwarden CLI"
    else:
        bw = config / "Bitwarden CLI"
    vw = Path(os.environ.get("VW_APPDATA_DIR", str(config / "vaultwarden-cli")))
    # The CI adapter deliberately maps BITWARDENCLI_APPDATA_DIR to VW_APPDATA_DIR.
    return tuple(
        dict.fromkeys((bw / "data.json", bw / "state.json", vw / "state.json"))
    )


def read_policy_state(
    status: Mapping[str, object],
    *,
    synced_after: datetime,
    candidates: Sequence[Path] | None = None,
) -> CliPolicyState:
    matches: list[CliPolicyState] = []
    for path in profile_candidates() if candidates is None else candidates:
        try:
            state = policy_object(json.loads(path.read_text(encoding="utf-8")))
            matches.append(parse_policy_state(state, status, synced_after=synced_after))
        except OSError, UnicodeError, ValueError, BitwardenClientError:
            continue
    if len(matches) != 1:
        raise BitwardenClientError(
            "Cannot verify SSH policy: no unique, freshly synchronized CLI profile"
        )
    return matches[0]
