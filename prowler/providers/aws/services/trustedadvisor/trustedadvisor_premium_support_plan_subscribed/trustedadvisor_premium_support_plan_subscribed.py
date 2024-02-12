from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_client import (
    trustedadvisor_client,
)


class trustedadvisor_premium_support_plan_subscribed(Check):
    def execute(self):
        findings = []
        if trustedadvisor_client.audit_config.get("verify_premium_support_plans", True):
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = (
                "Amazon Web Services Premium Support Plan isn't subscribed."
            )
            report.region = trustedadvisor_client.region
            report.resource_id = trustedadvisor_client.audited_account
            report.resource_arn = f"arn:{trustedadvisor_client.audited_partition}:trusted-advisor:{trustedadvisor_client.region}:{trustedadvisor_client.audited_account}:account"
            if trustedadvisor_client.premium_support.enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Amazon Web Services Premium Support Plan is subscribed."
                )
            findings.append(report)
        return findings
