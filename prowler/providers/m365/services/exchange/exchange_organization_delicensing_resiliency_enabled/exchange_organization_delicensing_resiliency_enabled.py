"""Check for Exchange Online Delicensing Resiliency configuration."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client

DELICENSING_LICENSE_THRESHOLD = 5000


class exchange_organization_delicensing_resiliency_enabled(Check):
    """
    Check if Delicensing Resiliency is enabled for Exchange Online.

    Delicensing Resiliency provides a grace period when licenses expire or are
    reassigned, preventing immediate mailbox access loss and allowing
    organizations time to manage licensing transitions.

    This feature is only available to tenants with 5000 or more paid licenses.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check for Delicensing Resiliency in Exchange Online.

        Iterates over the Exchange Online organization configuration and
        evaluates whether Delicensing Resiliency is enabled, taking into
        account the tenant's paid license count.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = exchange_client.organization_config
        if organization_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )

            if organization_config.delayed_delicensing_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Delicensing Resiliency is enabled for Exchange Online, "
                    "providing a grace period when licenses are removed."
                )
            elif (
                organization_config.total_paid_licenses is not None
                and organization_config.total_paid_licenses
                < DELICENSING_LICENSE_THRESHOLD
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Delicensing Resiliency is not applicable for this tenant. "
                    f"The tenant has {organization_config.total_paid_licenses} "
                    f"total licenses, which is below the "
                    f"{DELICENSING_LICENSE_THRESHOLD} paid license threshold "
                    f"required by Microsoft for this feature."
                )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    "Delicensing Resiliency is not enabled for Exchange Online. "
                    "This feature is only available to tenants with 5000 or more "
                    "paid licenses. Verify whether the tenant qualifies and "
                    "enable Delicensing Resiliency if applicable."
                )

            findings.append(report)

        return findings
