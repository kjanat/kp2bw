"""SSH policy decisions match membership and target-vault restrictions."""

from kp2bw._ssh_policy import PolicyObject, require_ssh_policy_allowed
from kp2bw.exceptions import BitwardenClientError


def main() -> None:
    member: dict[str, object] = {
        "id": "org-a",
        "status": 2,
        "enabled": True,
        "usePolicies": True,
        "type": 2,
    }
    other: dict[str, object] = {**member, "id": "org-b"}
    restriction: dict[str, object] = {
        "organizationId": "org-a",
        "type": 15,
        "enabled": True,
        "data": [5],
    }

    def rejected(
        organizations: list[PolicyObject],
        policies: list[PolicyObject],
        target: str | None,
    ) -> None:
        try:
            require_ssh_policy_allowed(organizations, policies, target)
        except BitwardenClientError:
            return
        raise AssertionError(
            "A restricted or unverifiable target must be rejected before mutation"
        )

    require_ssh_policy_allowed([], [], None)
    rejected([member], [restriction], None)
    rejected([member], [restriction], "org-a")
    require_ssh_policy_allowed([member, other], [restriction], "ORG-B")
    require_ssh_policy_allowed([member], [{**restriction, "enabled": False}], None)
    require_ssh_policy_allowed([member], [{**restriction, "data": None}], None)
    for role in (0, 1):
        require_ssh_policy_allowed([{**member, "type": role}], [restriction], "org-a")
    for patch in (
        {"enabled": False},
        {"usePolicies": False},
        {"status": 0},
        {"isProviderUser": True},
    ):
        require_ssh_policy_allowed([{**member, **patch}], [restriction], None)
    rejected([], [restriction], None)
    rejected([member], [{**restriction, "data": "[5]"}], None)
    rejected([member], [{**restriction, "data": "invalid"}], None)
    rejected([member], [{**restriction, "data": [True]}], None)
    rejected([{"id": "org-a"}], [restriction], None)
    rejected([member], [], "unknown-org")
    rejected([member], [{**restriction, "type": 5}], None)
    require_ssh_policy_allowed([member], [{**restriction, "type": 5}], "org-a")
    print("SSH policy tests passed")


if __name__ == "__main__":
    main()
