from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


def _join_human_readable(items: List[str]) -> str:
    """Return a simple human readable comma-separated list."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


class organization_repository_creation_limited(Check):
    """Check if repository creation is limited to trusted organization members."""

    def execute(self) -> List[CheckReportGithub]:
        findings = []
        for org in organization_client.organizations.values():
            repo_data = [
                getattr(org, "members_can_create_repositories", None),
                getattr(org, "members_can_create_public_repositories", None),
                getattr(org, "members_can_create_private_repositories", None),
                getattr(org, "members_can_create_internal_repositories", None),
                getattr(org, "members_allowed_repository_creation_type", None),
            ]

            if all(value is None for value in repo_data):
                continue

            report = CheckReportGithub(metadata=self.metadata(), resource=org)

            global_creation = getattr(org, "members_can_create_repositories", None)
            public_creation = getattr(
                org, "members_can_create_public_repositories", None
            )
            private_creation = getattr(
                org, "members_can_create_private_repositories", None
            )
            internal_creation = getattr(
                org, "members_can_create_internal_repositories", None
            )
            creation_type = getattr(
                org, "members_allowed_repository_creation_type", None
            )

            type_flags = []
            enabled_types = []

            if global_creation is not None:
                if global_creation:
                    enabled_types.append("repositories of any type")
                else:
                    type_flags.append(False)

            visibility_flags = [
                (public_creation, "public repositories"),
                (private_creation, "private repositories"),
                (internal_creation, "internal repositories"),
            ]

            for flag, label in visibility_flags:
                if flag is not None:
                    type_flags.append(flag)
                    if flag:
                        enabled_types.append(label)

            if creation_type:
                normalized_type = creation_type.lower()
                if normalized_type == "none":
                    type_flags.append(False)
                else:
                    creation_messages = {
                        "all": "repositories of any type",
                        "public": "public repositories",
                        "private": "private repositories",
                        "internal": "internal repositories",
                        "selected": "repositories for selected members or teams",
                    }
                    enabled_types.append(
                        creation_messages.get(
                            normalized_type, f"{creation_type} repositories"
                        )
                    )

            restricted = bool(type_flags) and all(flag is False for flag in type_flags)

            if restricted:
                report.status = "PASS"
                report.status_extended = f"Organization {org.name} has disabled repository creation for members."
            else:
                report.status = "FAIL"
                unique_enabled = list(dict.fromkeys(enabled_types))
                allowed_desc = _join_human_readable(unique_enabled)
                if allowed_desc:
                    report.status_extended = f"Organization {org.name} allows members to create {allowed_desc}."
                else:
                    report.status_extended = f"Organization {org.name} does not have enough data to confirm repository creation restrictions."

            findings.append(report)

        return findings
