from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)
from prowler.providers.aws.services.inspector2.lib.vulnerabilities import (
    summarize_vulnerabilities,
)


class inspector2_active_findings_kev_within_due_date(Check):
    """Ensure active Inspector2 findings for CISA KEVs are not past their CISA due date."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        now = datetime.now(timezone.utc)
        known_exploited = inspector2_client.known_exploited_vulnerabilities
        lookup_failed = inspector2_client.vulnerability_lookup_failed
        for inspector in inspector2_client.inspectors:
            if inspector.status != "ENABLED":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=inspector)
            if inspector.findings is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Inspector2 findings could not be retrieved in region {inspector.region}; "
                    "verify the inspector2:ListFindings permission."
                )
                findings.append(report)
                continue
            vulnerability_ids = {
                finding.vulnerability_id
                for finding in inspector.findings
                if finding.vulnerability_id
            }
            overdue = sorted(
                f"{vulnerability_id} (due {known_exploited[vulnerability_id].date_due.date().isoformat()})"
                for vulnerability_id in known_exploited.keys() & vulnerability_ids
                if known_exploited[vulnerability_id].date_due
                and known_exploited[vulnerability_id].date_due < now
            )
            unverified_ids = sorted(vulnerability_ids & lookup_failed)
            if overdue:
                report.status = "FAIL"
                report.status_extended = (
                    f"Inspector2 has active findings in region {inspector.region} for CISA "
                    "Known Exploited Vulnerabilities past their remediation due date: "
                    f"{summarize_vulnerabilities(overdue)}."
                )
            elif unverified_ids:
                report.status = "MANUAL"
                report.status_extended = (
                    "Inspector2 could not verify the CISA Known Exploited Vulnerabilities status of "
                    f"{summarize_vulnerabilities(unverified_ids)} in region {inspector.region}; "
                    "verify the inspector2:SearchVulnerabilities permission."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Inspector2 has no active findings in region {inspector.region} for CISA "
                    "Known Exploited Vulnerabilities past their remediation due date."
                )
            findings.append(report)
        return findings
