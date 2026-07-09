from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_ensure_http_is_redirected_to_https(Check):
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
                report.status_extended = f"Function {function.name} from subscription {subscription_name} ({subscription_id}) does not have HTTP redirected to HTTPS."
                if function.https_only:
                    report.status = "PASS"
                    report.status_extended = f"Function {function.name} from subscription {subscription_name} ({subscription_id}) has HTTP redirected to HTTPS."

                findings.append(report)

        return findings
