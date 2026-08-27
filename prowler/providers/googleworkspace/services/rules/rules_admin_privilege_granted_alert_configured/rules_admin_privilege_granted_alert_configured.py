from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.rules.lib.alerts import (
    evaluate_system_defined_alert,
)
from prowler.providers.googleworkspace.services.rules.rules_client import (
    rules_client,
)

RULE_NAME = "User granted Admin privilege"
EXPECTED_SEVERITIES = {"MEDIUM"}


class rules_admin_privilege_granted_alert_configured(Check):
    """Check that the User granted Admin privilege system-defined alert rule is fully configured.

    CIS 6.4 requires the rule to be on, to notify by email, to include all
    super administrators as recipients and to be set to MEDIUM severity.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        return evaluate_system_defined_alert(
            rules_client, self.metadata(), RULE_NAME, EXPECTED_SEVERITIES
        )
