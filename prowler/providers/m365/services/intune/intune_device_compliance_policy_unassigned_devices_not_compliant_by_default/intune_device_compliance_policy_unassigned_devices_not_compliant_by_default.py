from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.intune.intune_client import intune_client


class intune_device_compliance_policy_unassigned_devices_not_compliant_by_default(
    Check
):
    """Ensure the built-in Device Compliance Policy marks unassigned devices as Not compliant by default."""

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=intune_client.settings or {},
            resource_name="Intune Device Compliance Settings",
            resource_id="deviceManagement/settings",
        )

        verification_error = getattr(intune_client, "verification_error", None)
        settings = getattr(intune_client, "settings", None)
        secure_by_default = getattr(settings, "secure_by_default", None)

        if verification_error:
            report.status = "MANUAL"
            report.status_extended = (
                "Intune built-in Device Compliance Policy could not be verified. "
                f"{verification_error}"
            )
        elif settings is None or secure_by_default is None:
            report.status = "MANUAL"
            report.status_extended = (
                "Intune built-in Device Compliance Policy could not be verified "
                "because Microsoft Graph did not return the secure-by-default "
                "compliance setting."
            )
        elif secure_by_default is True:
            report.status = "PASS"
            report.status_extended = (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as Not compliant."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Intune built-in Device Compliance Policy marks devices "
                "with no compliance policy assigned as Compliant. "
                "Change the default to Not compliant in Intune settings."
            )

        findings.append(report)
        return findings
