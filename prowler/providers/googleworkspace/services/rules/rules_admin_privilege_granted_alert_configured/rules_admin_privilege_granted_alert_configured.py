from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.rules.rules_client import (
    rules_client,
)

RULE_NAME = "User granted Admin privilege"


class rules_admin_privilege_granted_alert_configured(Check):
    """Check that the User granted Admin privilege system-defined alert rule is fully configured."""

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if rules_client.policies_fetched:
            for alert in rules_client.system_defined_alerts:
                if alert.display_name != RULE_NAME:
                    continue

                domain = rules_client.provider.identity.domain
                report = CheckReportGoogleWorkspace(
                    metadata=self.metadata(),
                    resource=alert,
                    resource_id="system_defined_alert",
                    resource_name=RULE_NAME,
                    customer_id=rules_client.provider.identity.customer_id,
                )

                is_active = alert.state == "ACTIVE"
                has_recipients = alert.email_notifications_enabled
                all_super_admins = alert.all_super_admins

                if is_active and has_recipients and all_super_admins:
                    report.status = "PASS"
                    report.status_extended = (
                        f"System-defined alert rule '{RULE_NAME}' is properly "
                        f"configured in domain {domain}: alert is ON, email "
                        f"notifications are enabled, and recipients include "
                        f"all super administrators."
                    )
                else:
                    report.status = "FAIL"
                    issues = []
                    if not is_active:
                        issues.append("alert is OFF")
                    if not has_recipients:
                        issues.append("email notifications are disabled")
                    elif not all_super_admins:
                        issues.append(
                            "email recipients do not include all super administrators"
                        )
                    report.status_extended = (
                        f"System-defined alert rule '{RULE_NAME}' is not properly "
                        f"configured in domain {domain}: {', '.join(issues)}."
                    )

                findings.append(report)

        return findings
