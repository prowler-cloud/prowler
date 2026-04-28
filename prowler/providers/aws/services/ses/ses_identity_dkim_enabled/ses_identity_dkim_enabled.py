from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ses.ses_client import ses_client


class ses_identity_dkim_enabled(Check):
    def execute(self):
        findings = []
        for identity in ses_client.email_identities.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=identity)
            if identity.dkim_status == "SUCCESS":
                report.status = "PASS"
                report.status_extended = (
                    f"SES identity {identity.name} has DKIM signing enabled and verified."
                )
            elif identity.dkim_status in ("PENDING", "NOT_STARTED", "TEMPORARY_FAILURE"):
                report.status = "FAIL"
                report.status_extended = (
                    f"SES identity {identity.name} has DKIM signing not verified (status: {identity.dkim_status})."
                )
            elif identity.dkim_status == "FAIL":
                report.status = "FAIL"
                report.status_extended = (
                    f"SES identity {identity.name} has DKIM signing failed verification."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SES identity {identity.name} does not have DKIM signing configured."
                )
            findings.append(report)

        return findings
