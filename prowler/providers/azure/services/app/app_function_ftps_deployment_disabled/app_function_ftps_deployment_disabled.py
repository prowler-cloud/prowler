from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_ftps_deployment_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            functions,
        ) in app_client.functions.items():
            subscription_name = app_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for function in functions.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=function)
                report.subscription = subscription_id
                report.status = "FAIL"
                report.status_extended = f"Function {function.name} from subscription {subscription_name} ({subscription_id}) has {'FTP' if function.ftps_state == 'AllAllowed' else 'FTPS' if function.ftps_state == 'FtpsOnly' else 'FTP or FTPS'} deployment enabled."
                if function.ftps_state == "Disabled":
                    report.status = "PASS"
                    report.status_extended = f"Function {function.name} from subscription {subscription_name} ({subscription_id}) has FTP and FTPS deployment disabled."

                findings.append(report)

        return findings
