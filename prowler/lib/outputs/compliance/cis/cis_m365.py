from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import M365CISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class M365CIS(ComplianceOutputBase):
    """This class represents the M365 CIS compliance output."""

    @property
    def model(self) -> Type[M365CISModel]:
        """Returns the specific M365CISModel.

        Returns:
            Type[M365CISModel]: The model class for compliance serialization.
        """
        return M365CISModel

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
