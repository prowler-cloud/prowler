from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.macie.macie_client import macie_client
from prowler.providers.aws.services.s3.s3_client import s3_client


class macie_is_enabled(Check):
    def execute(self):
        findings = []
        for session in macie_client.sessions:
            report = Check_Report_AWS(self.metadata())
            report.region = session.region
            report.resource_arn = macie_client.audited_account_arn
            report.resource_id = macie_client.audited_account
            if session.status == "ENABLED":
                report.status = "PASS"
                report.status_extended = "Macie is enabled."
                findings.append(report)
            else:
                if s3_client.audit_info.ignore_unused_services:
                    buckets_in_region = False
                    for bucket in s3_client.buckets:
                        if bucket.region == session.region:
                            buckets_in_region = True
                            break
                if not s3_client.audit_info.ignore_unused_services or buckets_in_region:
                    if session.status == "PAUSED":
                        report.status = "FAIL"
                        report.status_extended = (
                            "Macie is currently in a SUSPENDED state."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = "Macie is not enabled."
                    findings.append(report)

        return findings
