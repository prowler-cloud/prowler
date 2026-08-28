from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.rules.lib.alerts import (
    evaluate_system_defined_alert,
)
from prowler.providers.googleworkspace.services.rules.rules_client import (
    rules_client,
)

RULE_NAME = "Suspicious login"
MINIMUM_SEVERITY = "LOW"


class rules_suspicious_login_alert_configured(Check):
    """Check that the Suspicious login system-defined alert rule is fully configured.

    CIS 6.6 requires the rule to be on, to notify by email, to include all
    super administrators as recipients and to be set to LOW severity or higher.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        return evaluate_system_defined_alert(
            rules_client, self.metadata(), RULE_NAME, MINIMUM_SEVERITY
        )
