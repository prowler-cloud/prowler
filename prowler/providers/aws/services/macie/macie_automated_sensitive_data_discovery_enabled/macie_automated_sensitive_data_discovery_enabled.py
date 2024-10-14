from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.macie.macie_client import macie_client


class macie_automated_sensitive_data_discovery_enabled(Check):
    def execute(self):
        findings = []
        for session in macie_client.sessions:
            if session.status == "ENABLED":
                report = Check_Report_AWS(self.metadata())
                report.region = session.region
                report.resource_arn = macie_client._get_session_arn_template(
                    session.region
                )
                report.resource_id = macie_client.audited_account
                report.status = "FAIL"
                report.status_extended = f"Macie does not have automated sensitive data discovery enabled in account: {macie_client.audited_account}."

                if session.automated_discovery_status == "ENABLED":
                    report.status = "PASS"
                    report.status_extended = f"Macie has automated sensitive data discovery enabled in account: {macie_client.audited_account}."

                findings.append(report)

        return findings
