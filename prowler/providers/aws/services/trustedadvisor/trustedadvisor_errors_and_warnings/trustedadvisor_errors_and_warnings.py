from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_client import (
    trustedadvisor_client,
)


class trustedadvisor_errors_and_warnings(Check):
    def execute(self):
        findings = []
        if trustedadvisor_client.premium_support:
            if trustedadvisor_client.premium_support.enabled:
                if trustedadvisor_client.checks:
                    for check in trustedadvisor_client.checks:
                        if (
                            check.status != "not_available"
                        ):  # avoid not_available checks since there are no resources that apply
                            report = Check_Report_AWS(self.metadata())
                            report.region = check.region
                            report.resource_id = check.id
                            report.resource_arn = check.arn
                            report.status = "FAIL"
                            report.status_extended = f"Trusted Advisor check {check.name} is in state {check.status}."
                            if check.status == "ok":
                                report.status = "PASS"
                            findings.append(report)
            else:
                report = Check_Report_AWS(self.metadata())
                report.status = "MANUAL"
                report.status_extended = "Amazon Web Services Premium Support Subscription is required to use this service."
                report.resource_id = trustedadvisor_client.audited_account
                report.resource_arn = trustedadvisor_client.account_arn_template
                report.region = trustedadvisor_client.region
                findings.append(report)

        return findings
