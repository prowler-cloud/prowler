from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.rules.lib.alerts import (
    evaluate_system_defined_alert,
)
from prowler.providers.googleworkspace.services.rules.rules_client import (
    rules_client,
)

RULE_NAME = "Leaked password"
MINIMUM_SEVERITY = "MEDIUM"


class rules_leaked_password_alert_configured(Check):
    """Check that the Leaked password system-defined alert rule is fully configured.

    CIS 6.7 requires the rule to be on, to notify by email, to include all
    super administrators as recipients and to be set to MEDIUM severity or higher.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        return evaluate_system_defined_alert(
            rules_client, self.metadata(), RULE_NAME, MINIMUM_SEVERITY
        )
