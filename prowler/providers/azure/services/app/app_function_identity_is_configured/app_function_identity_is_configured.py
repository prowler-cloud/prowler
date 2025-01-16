from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_identity_is_configured(Check):
    def execute(self):
        findings = []

        for (
            subscription_name,
            functions,
        ) in app_client.functions.items():
            for function in functions.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=function
                )
                report.subscription = subscription_name
                report.status = "FAIL"
                report.status_extended = f"Function {function.name} does not have a managed identity enabled."

                if function.identity:
                    report.status = "PASS"
                    report.status_extended = f"Function {function.name} has a {function.identity.type if getattr(function.identity, 'type', '') else 'managed'} identity enabled."

                findings.append(report)

        return findings
