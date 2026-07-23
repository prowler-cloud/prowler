from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# CIS recommends an idle session timeout of 3 hours or less.
MAX_IDLE_TIMEOUT_SECONDS = 3 * 60 * 60


class entra_idle_session_timeout_configured(Check):
    """Check if an idle session timeout of 3 hours or less is configured.

    An activity-based timeout policy should sign out inactive users from Microsoft
    365 web apps after a period of inactivity. The web session idle timeout should be
    set to 3 hours or less.

    - PASS: An activity-based timeout policy enforces an idle timeout of 3 hours or
      less.
    - FAIL: No activity-based timeout policy enforces an idle timeout of 3 hours or
      less.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        policies = entra_client.activity_based_timeout_policies

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policies if policies else {},
            resource_name="Activity Based Timeout Policies",
            resource_id="activityBasedTimeoutPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No activity-based timeout policy enforces an idle session timeout of 3 "
            "hours or less."
        )

        for policy in policies:
            timeout = policy.web_session_idle_timeout_seconds
            if timeout is not None and timeout <= MAX_IDLE_TIMEOUT_SECONDS:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name
                    or "Activity Based Timeout Policy",
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Activity-based timeout policy '{policy.display_name or policy.id}' "
                    f"enforces an idle session timeout of {timeout // 60} minutes."
                )
                break

        findings.append(report)
        return findings
