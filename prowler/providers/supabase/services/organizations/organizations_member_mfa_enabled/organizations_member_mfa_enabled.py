from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_member_mfa_enabled(Check):
    """Check whether each Supabase organization member has MFA enabled."""

    def execute(self) -> list[CheckReportSupabase]:
        """Return one MFA finding per organization member."""
        findings = []
        for member in organizations_client.members.values():
            report = CheckReportSupabase(metadata=self.metadata(), resource=member)
            if member.mfa_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Supabase organization {member.organization_slug} member "
                    f"{member.id} has MFA enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Supabase organization {member.organization_slug} member "
                    f"{member.id} does not have MFA enabled."
                )
            findings.append(report)
        return findings
