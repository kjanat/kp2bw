"""Evaluate synced item-type policies before writing a native SSH item."""

import json
from collections.abc import Mapping, Sequence
from typing import cast

from .exceptions import BitwardenClientError

type PolicyObject = Mapping[str, object]


def _identifier(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and value else None


def _applies(organization: PolicyObject | None) -> bool:
    # Match the Bitwarden SDK / vaultwarden library membership exemptions.
    # A policy without its membership context remains enforced.
    if organization is None:
        return True
    required = ("status", "enabled", "usePolicies", "type")
    if any(key not in organization for key in required):
        raise BitwardenClientError(
            "Cannot verify SSH policy: organization membership is incomplete"
        )
    return (
        organization["status"] in (1, 2)
        and organization["enabled"] is True
        and organization["usePolicies"] is True
        and organization["type"] not in (0, 1)
        and organization.get("isProviderUser") is not True
    )


def _restricted_types(policy: PolicyObject) -> frozenset[int]:
    data = policy.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            raise BitwardenClientError(
                "Cannot verify SSH policy: invalid item-type policy data"
            ) from None
    if data is None:
        return frozenset({3})  # Upstream's default restriction is cards.
    if not isinstance(data, list):
        raise BitwardenClientError(
            "Cannot verify SSH policy: invalid item-type restrictions"
        )
    values = cast(list[object], data)
    if any(type(item) is not int for item in values):
        raise BitwardenClientError(
            "Cannot verify SSH policy: invalid item-type restrictions"
        )
    return frozenset(cast(list[int], data))


def require_ssh_policy_allowed(
    organizations: Sequence[PolicyObject],
    policies: Sequence[PolicyObject],
    organization_id: str | None,
) -> None:
    """Apply type-15 restrictions and personal-ownership policy before mutation.

    An applicable restriction blocks personal SSH items and SSH items in the
    restricting organization. A different organization without that restriction
    remains allowed, matching both clients' item visibility rules.
    """
    memberships = {_identifier(org.get("id")): org for org in organizations}
    if None in memberships:
        raise BitwardenClientError(
            "Cannot verify SSH policy: invalid organization identity"
        )
    target = _identifier(organization_id)
    if target is not None and target not in memberships:
        raise BitwardenClientError(
            "Cannot verify SSH policy: target organization is not in the synced profile"
        )
    restricted: set[str] = set()
    for policy in policies:
        if policy.get("enabled") is not True or policy.get("type") not in (5, 15):
            continue
        identifier = _identifier(policy.get("organizationId"))
        if identifier is None:
            raise BitwardenClientError(
                "Cannot verify SSH policy: policy has no organization identity"
            )
        if not _applies(memberships.get(identifier)):
            continue
        if policy["type"] == 5 and target is None:
            raise BitwardenClientError(
                "Organization policy forbids personal-vault SSH items"
            )
        if policy["type"] == 15 and 5 in _restricted_types(policy):
            restricted.add(identifier)
    if restricted and (target is None or target in restricted):
        raise BitwardenClientError(
            "Organization policy forbids SSH items in the selected vault"
        )
