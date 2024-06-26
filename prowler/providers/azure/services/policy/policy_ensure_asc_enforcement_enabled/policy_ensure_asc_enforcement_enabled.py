from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_asc_enforcement_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, policies in policy_client.policy_assigments.items():
            if "SecurityCenterBuiltIn" in policies:
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = "SecurityCenterBuiltIn"
                report.resource_id = policies["SecurityCenterBuiltIn"].id
                report.status_extended = f"Policy assigment '{policies['SecurityCenterBuiltIn'].id}' is configured with enforcement mode '{policies['SecurityCenterBuiltIn'].enforcement_mode}'."

                if policies["SecurityCenterBuiltIn"].enforcement_mode != "Default":
                    report.status = "FAIL"
                    report.status_extended = f"Policy assigment '{policies['SecurityCenterBuiltIn'].id}' is not configured with enforcement mode Default."

                findings.append(report)

        return findings
