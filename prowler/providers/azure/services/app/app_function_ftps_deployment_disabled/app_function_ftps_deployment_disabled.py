from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_ftps_deployment_disabled(Check):
    def execute(self) -> Check_Report_Azure:
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
                report.status_extended = f"Function {function.name} has {'FTP' if function.ftps_state == 'AllAllowed' else 'FTPS' if function.ftps_state == 'FtpsOnly' else 'FTP or FTPS'} deployment enabled"
                if function.ftps_state == "Disabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"Function {function.name} has FTP and FTPS deployment disabled"
                    )

                findings.append(report)

        return findings
