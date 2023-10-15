from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_client import (
    trustedadvisor_client,
)


class trustedadvisor_support_plan_subscribed(Check):
    def execute(self):
        findings = []
        if trustedadvisor_client.audit_config.get("verify_premium_support_plans"):
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "Premium support plan isn't subscribed."
            report.region = trustedadvisor_client.region
            report.resource_id = trustedadvisor_client.audited_account
            report.resource_arn = trustedadvisor_client.audited_account_arn
            for support_service in trustedadvisor_client.support_services:
                if support_service.premium_support:
                    report.status = "PASS"
                    report.status_extended = "Premium support plan is subscribed."
                    break
            findings.append(report)
        return findings
