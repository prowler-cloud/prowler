from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_forms_phishing_protection_enabled(Check):
    """Check if Microsoft Forms internal phishing protection is enabled.

    The Microsoft Forms org settings should have internal phishing protection
    (``isInOrgFormsPhishingScanEnabled``) enabled so forms are scanned for phishing
    keywords.

    - PASS: Microsoft Forms internal phishing protection is enabled.
    - FAIL: Microsoft Forms internal phishing protection is disabled.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = admincenter_client.forms_settings
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="Microsoft Forms Settings",
            resource_id="formsSettings",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Microsoft Forms internal phishing protection is not enabled."
        )

        if settings.in_org_forms_phishing_scan_enabled:
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Forms internal phishing protection is enabled."
            )

        findings.append(report)
        return findings
