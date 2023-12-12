from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.securityhub.securityhub_client import (
    securityhub_client,
)


class securityhub_enabled(Check):
    def execute(self):
        findings = []
        for securityhub in securityhub_client.securityhubs:
            report = Check_Report_AWS(self.metadata())
            report.region = securityhub.region
            report.resource_id = securityhub.id
            report.resource_arn = securityhub.arn
            if securityhub.status == "ACTIVE":
                report.status = "PASS"
                if securityhub.standards:
                    report.status_extended = f"Security Hub is enabled with standards: {securityhub.standards}."
                elif securityhub.integrations:
                    report.status_extended = f"Security Hub is enabled without standards but with integrations: {securityhub.integrations}."
                else:
                    report.status = "FAIL"
                    report.status_extended = "Security Hub is enabled but without any standard or integration."
            else:
                report.status = "FAIL"
                report.status_extended = "Security Hub is not enabled."

            if report.status == "FAIL" and (
                securityhub_client.audit_config.get("mute_non_default_regions", False)
                and not securityhub.region == securityhub_client.region
            ):
                report.status = "MUTED"

            findings.append(report)

        return findings
