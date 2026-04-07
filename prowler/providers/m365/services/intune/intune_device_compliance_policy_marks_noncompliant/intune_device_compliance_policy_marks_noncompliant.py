from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.intune.intune_client import intune_client


class intune_device_compliance_policy_marks_noncompliant(Check):
    """Ensure the built-in Device Compliance Policy marks devices with no compliance policy assigned as 'Not compliant'."""

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=intune_client.settings or {},
            resource_name="Intune Device Compliance Settings",
            resource_id="deviceManagement/settings",
        )

        if intune_client.settings and intune_client.settings.secure_by_default is True:
            report.status = "PASS"
            report.status_extended = (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as 'Not compliant'."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as 'Compliant'. "
                "Change the default to 'Not compliant' in Intune settings."
            )

        findings.append(report)
        return findings
