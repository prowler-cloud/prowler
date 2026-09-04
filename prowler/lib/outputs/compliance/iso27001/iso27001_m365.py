from typing import Optional, Type
from prowler.lib.check.compliance_models import Compliance_Requirement
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.iso27001.models import M365ISO27001Model
from prowler.lib.outputs.finding import Finding


class M365ISO27001(ComplianceOutputBase):
    """This class represents the M365 ISO 27001 compliance output."""

    @property
    def model(self) -> Type[M365ISO27001Model]:
        """Returns the specific M365ISO27001Model.

        Returns:
            Type[M365ISO27001Model]: The model class for compliance serialization.
        """
        return M365ISO27001Model

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "TenantId": "",
                "Location": "",
            }
        return {
            "TenantId": finding.account_uid,
            "Location": finding.region,
        }

    def get_framework_specific_fields(
        self, requirement: Compliance_Requirement
    ) -> dict[str, str]:
        """Returns the framework specific fields for the compliance output."""
        return {
            "Requirements_Name": requirement.Name or "",
        }

