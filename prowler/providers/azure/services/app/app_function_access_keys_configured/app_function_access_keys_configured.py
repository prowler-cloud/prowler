from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_access_keys_configured(Check):
    def execute(self):
        findings = []

        for (
            subscription_name,
            functions,
        ) in app_client.functions.items():
            for function_id, function in functions.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.status_extended = (
                    f"Function {function.name} does not have function keys configured."
                )
                report.subscription = subscription_name
                report.resource_name = function.name
                report.resource_id = function_id
                report.location = function.location

                if len(function.function_keys) > 0:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Function {function.name} has function keys configured."
                    )

                findings.append(report)

        return findings
