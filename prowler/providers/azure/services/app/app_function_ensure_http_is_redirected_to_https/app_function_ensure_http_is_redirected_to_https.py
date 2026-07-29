from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_function_ensure_http_is_redirected_to_https(Check):
    """Ensure Function Apps redirect HTTP traffic to HTTPS."""

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the check logic.

        Returns:
            A list of reports for Function Apps HTTPS-only enforcement.
        """
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
                report.status = "PASS"
                report.status_extended = f"HTTP is redirected to HTTPS for Function app '{function.name}' in subscription '{subscription_name} ({subscription_id})'."

                if not function.https_only:
                    report.status = "FAIL"
                    report.status_extended = f"HTTP is not redirected to HTTPS for Function app '{function.name}' in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
