"""Policy cache reads are bound to the active account, server and fresh sync."""

import copy
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from kp2bw._cli_policy_state import parse_policy_state, read_policy_state
from kp2bw.exceptions import BitwardenClientError


def main() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    timestamp = "2026-01-01T00:00:01Z"
    status: dict[str, object] = {
        "userId": "user",
        "serverUrl": "https://vault.example.test",
        "status": "unlocked",
        "lastSync": timestamp,
    }
    official: dict[str, object] = {
        "global_account_activeAccountId": "user",
        "user_user_sync_lastSync": timestamp,
        "user_user_environment_environment": {
            "region": "Self-hosted",
            "urls": {"base": "https://vault.example.test"},
        },
        "user_user_organizations_organizations": {},
        "user_user_policies_policies": {},
        "user_user_policies_policiesNew": {},
        "user_user_token_accessToken": "must-not-be-returned",
    }
    replacement: dict[str, object] = {
        "version": 1,
        "server": "https://vault.example.test",
        "lastSync": timestamp,
        "vault": {"profile": {"id": "user", "organizations": []}, "policies": []},
        "account": {"accessToken": "must-not-be-returned"},
    }
    for state, kind in ((official, "bitwarden"), (replacement, "vaultwarden")):
        metadata = parse_policy_state(state, status, synced_after=started)
        assert (
            metadata.kind == kind
            and metadata.api_url == "https://vault.example.test/api"
        )
        assert not metadata.organizations and not metadata.policies
        assert "must-not-be-returned" not in repr(metadata)
        assert metadata.premium is None
        for changed in (
            {"userId": "other"},
            {"serverUrl": "https://other.example.test"},
            {"status": "locked"},
            {"lastSync": "2025-12-31T23:59:59Z"},
            {"lastSync": "2026-01-01T00:00:02Z"},
        ):
            try:
                parse_policy_state(state, {**status, **changed}, synced_after=started)
            except BitwardenClientError:
                pass
            else:
                raise AssertionError("Mismatched or stale CLI metadata was accepted")
    missing = copy.deepcopy(official)
    del missing["user_user_policies_policies"]
    try:
        parse_policy_state(missing, status, synced_after=started)
    except BitwardenClientError:
        pass
    else:
        raise AssertionError("Missing policies must not become an empty allow list")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "data.json"
        path.write_text(json.dumps(official))
        assert (
            read_policy_state(status, synced_after=started, candidates=[path]).kind
            == "bitwarden"
        )
        duplicate = Path(directory) / "state.json"
        duplicate.write_text(json.dumps(replacement))
        try:
            read_policy_state(
                status, synced_after=started, candidates=[path, duplicate]
            )
        except BitwardenClientError:
            pass
        else:
            raise AssertionError(
                "Ambiguous profiles must not select a policy source arbitrarily"
            )
    for personal, organization, expected in (
        (False, False, False),
        (True, False, True),
        (False, True, True),
        (None, False, None),
    ):
        metadata = parse_policy_state(
            {
                **official,
                "user_user_billing_accountProfile": {
                    "hasPremiumPersonally": personal,
                    "hasPremiumFromAnyOrganization": organization,
                },
            },
            status,
            synced_after=started,
        )
        assert metadata.premium is expected
        metadata = parse_policy_state(
            {
                **replacement,
                "vault": {
                    "profile": {
                        "id": "user",
                        "organizations": [],
                        "premium": personal,
                        "premiumFromOrganization": organization,
                    },
                    "policies": [],
                },
            },
            status,
            synced_after=started,
        )
        assert metadata.premium is expected
    print("CLI policy state tests passed")


if __name__ == "__main__":
    main()
