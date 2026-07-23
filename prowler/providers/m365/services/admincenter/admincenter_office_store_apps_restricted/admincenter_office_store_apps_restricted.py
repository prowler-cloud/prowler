from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_office_store_apps_restricted(Check):
    """Check if users are restricted from accessing the Office Store and trials.

    The org-wide apps and services settings should have both **Office Store access**
    (``isOfficeStoreEnabled``) and **trials on behalf of the organization**
    (``isAppAndServicesTrialEnabled``) disabled.

    - PASS: Both Office Store access and trials are disabled.
    - FAIL: Office Store access and/or trials are enabled.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = admincenter_client.apps_and_services_settings
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="Apps and Services Settings",
            resource_id="appsAndServicesSettings",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Users are allowed to access the Office Store and/or start trials."
        )

        if (
            not settings.office_store_enabled
            and not settings.app_and_services_trial_enabled
        ):
            report.status = "PASS"
            report.status_extended = (
                "Users are not allowed to access the Office Store or start trials."
            )

        findings.append(report)
        return findings
