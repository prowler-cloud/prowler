from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_auth_is_set_up(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_id,
            apps,
        ) in app_client.apps.items():
            subscription_name = app_client.subscriptions.get(
                subscription_id, subscription_id
            )
            unreadable_apps = [
                app.resource_id for app in apps.values() if app.auth_enabled is None
            ]
            if unreadable_apps:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription_id
                report.resource_name = subscription_name
                report.resource_id = f"/subscriptions/{subscription_id}"
                report.status = "MANUAL"
                report.status_extended = (
                    f"App authentication settings could not be retrieved for apps {', '.join(unreadable_apps)} "
                    f"in subscription '{subscription_name} ({subscription_id})'. "
                    "Verify Microsoft.Web/sites/config/list/Action access and retry the scan."
                )
                findings.append(report)

            for app in apps.values():
                if app.auth_enabled is None:
                    continue
                report = Check_Report_Azure(metadata=self.metadata(), resource=app)
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Authentication is set up for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                if not app.auth_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Authentication is not set up for app '{app.name}' in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
