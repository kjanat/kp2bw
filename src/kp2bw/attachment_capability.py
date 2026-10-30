"""Attachment entitlement metadata; unknown free storage is never inferred."""

import math
from dataclasses import dataclass

from .cli_policy_state import CliPolicyState


@dataclass(frozen=True)
class AttachmentCapability:
    allowed: bool | None
    storage_limit_bytes: int | None = None
    free_storage_bytes: int | None = None
    reason: str = "Free storage is not exposed by synchronized CLI metadata"


def attachment_capability(
    state: CliPolicyState, organization_id: str | None
) -> AttachmentCapability:
    if organization_id is None:
        return AttachmentCapability(
            state.premium,
            reason="Personal attachment uploads require premium entitlement"
            if state.premium is False
            else "Free personal storage is not exposed by synchronized CLI metadata",
        )
    matches = [org for org in state.organizations if org.get("id") == organization_id]
    if len(matches) != 1:
        return AttachmentCapability(
            None, reason="No unique organization membership was found"
        )
    org = matches[0]
    if org.get("enabled") is False or (
        org.get("status") is not None and org.get("status") != 2
    ):
        return AttachmentCapability(
            False, reason="Organization membership is disabled or not confirmed"
        )
    maximum = org.get("maxStorageGb")
    if (
        type(maximum) in (int, float)
        and isinstance(maximum, (int, float))
        and math.isfinite(maximum)
        and maximum >= 0
    ):
        limit = int(maximum * 1024**3)
        return AttachmentCapability(
            limit > 0,
            storage_limit_bytes=limit,
            reason="The organization has no attachment storage"
            if limit == 0
            else "Organization storage limit is known; available space is not exposed",
        )
    return AttachmentCapability(
        None,
        reason="Organization attachment entitlement and available space could not be verified",
    )
