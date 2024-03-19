from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_http_logs_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, apps in app_client.apps.items():
            for app_name, app in apps.items():
                subscription_name = subscription
                is_web_app = False
                if not app.monitor_diagnostic_settings:
                    report = Check_Report_Azure(self.metadata())
                    report.status = "FAIL"
                    report.subscription = subscription_name
                    report.resource_name = app_name
                    report.resource_id = app.resource_id
                    report.status_extended = f"Logging for app {app_name} HTTP Logs is disabled in subscription {subscription_name}."
                    findings.append(report)
                else:
                    for diagnostic_setting in app.monitor_diagnostic_settings:
                        report = Check_Report_Azure(self.metadata())
                        report.subscription = subscription_name
                        report.resource_name = diagnostic_setting.name
                        report.resource_id = diagnostic_setting.id
                        report.status = "FAIL"
                        report.status_extended = f"Diagnostic setting {diagnostic_setting.name} has not logging for app {app_name} HTTP Logs enabled in subscription {subscription_name}"
                        for log in diagnostic_setting.logs:
                            log.category == "AppServiceHTTPLogs"
                            is_web_app = True
                        for log in diagnostic_setting.logs:
                            if log.category == "AppServiceHTTPLogs" and log.enabled:
                                report.status = "PASS"
                                report.status_extended = f"Diagnostic setting {diagnostic_setting.name} has logging for app {app_name} HTTP Logs enabled in subscription {subscription_name}"
                                break
                        if report.status == "PASS":
                            break
                    if is_web_app:
                        findings.append(report)

        return findings
