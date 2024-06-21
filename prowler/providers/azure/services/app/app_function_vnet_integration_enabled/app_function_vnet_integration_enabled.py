from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_vnet_integration_enabled(Check):
    def execute(self):
        findings = []

        for (
            subscription_name,
            functions,
        ) in app_client.functions.items():
            for function_id, function in functions.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.status_extended = f"Function {function.name} does not have virtual network integration enabled."
                report.subscription = subscription_name
                report.resource_name = function.name
                report.resource_id = function_id
                report.location = function.location

                if function.vnet_subnet_id:
                    report.status = "PASS"
                    report.status_extended = f"Function {function.name} has Virtual Network integration enabled with subnet '{function.vnet_subnet_id}' enabled."

                findings.append(report)

        return findings
