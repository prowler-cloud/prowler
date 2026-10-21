from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.groups.groups_client import (
    groups_client,
)


class groups_creation_restricted(Check):
    """Check that group creation is restricted to admins only with no external members or incoming email.

    This check verifies three sub-settings:
    - Only organization admins can create groups (not all users)
    - Group owners cannot allow external members
    - Group owners cannot allow incoming email from outside the organization

    When Groups for Business is off for everyone, nobody can create a group in
    the Google Groups app, so the creation setting is moot. Existing groups
    stay active and keep receiving mail, so the other two settings still count.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if groups_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=groups_client.policies,
                resource_id="groupsPolicies",
                resource_name="Groups Policies",
                customer_id=groups_client.provider.identity.customer_id,
            )

            policies = groups_client.policies
            domain = groups_client.provider.identity.domain

            access_level = policies.create_groups_access_level
            external_members = policies.owners_can_allow_external_members
            incoming_mail = policies.owners_can_allow_incoming_mail_from_public

            issues = []
            service_off = policies.off_for_everyone

            # Check creation access level
            # Default is USERS_IN_DOMAIN (insecure) — only ADMIN_ONLY is compliant.
            # Moot while the service is off: nobody can create a group then.
            if not service_off and access_level != "ADMIN_ONLY":
                effective = access_level or "USERS_IN_DOMAIN (default)"
                issues.append(
                    f"group creation is set to {effective} instead of ADMIN_ONLY"
                )

            # Check external members
            # Default is false (secure) — only false is compliant
            if external_members is True:
                issues.append("group owners can allow external members")

            # Check incoming mail from outside
            # Default is false (secure) — only true is non-compliant
            if incoming_mail is True:
                issues.append(
                    "group owners can allow incoming email from outside the organization"
                )

            if not issues and service_off:
                report.status = "PASS"
                report.status_extended = (
                    f"Groups for Business is turned off for everyone in domain "
                    f"{domain}, so no group can be created, and existing groups "
                    f"allow no external members and no incoming email from outside."
                )
            elif not issues:
                report.status = "PASS"
                report.status_extended = (
                    f"Group creation is properly restricted in domain {domain}: "
                    f"admin-only creation, no external members, "
                    f"no incoming email from outside."
                )
            elif service_off:
                report.status = "FAIL"
                issues_text = "; ".join(issues)
                report.status_extended = (
                    f"Groups for Business is turned off for everyone in domain "
                    f"{domain}, so no group can be created, but existing groups "
                    f"remain active and are not fully restricted: {issues_text}."
                )
            else:
                report.status = "FAIL"
                issues_text = "; ".join(issues)
                report.status_extended = (
                    f"Group creation is not fully restricted "
                    f"in domain {domain}: {issues_text}."
                )

            findings.append(report)

        return findings
