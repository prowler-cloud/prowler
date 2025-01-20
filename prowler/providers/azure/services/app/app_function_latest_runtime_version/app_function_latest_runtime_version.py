from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_latest_runtime_version(Check):
    def execute(self):
        findings = []

        for (
            subscription_name,
            functions,
        ) in app_client.functions.items():
            for function in functions.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=function)
                report.subscription = subscription_name
                report.status = "PASS"
                report.status_extended = (
                    f"Function {function.name} is using the latest runtime."
                )

                if (
                    function.enviroment_variables.get("FUNCTIONS_EXTENSION_VERSION", "")
                    != "~4"
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Function {function.name} is not using the latest runtime. The current runtime is '{function.enviroment_variables.get('FUNCTIONS_EXTENSION_VERSION', '')}' and should be '~4'."

                findings.append(report)

        return findings
