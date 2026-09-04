from typing import Optional, Type
from prowler.lib.outputs.compliance.ccc.models import CCC_GCPModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class CCC_GCP(ComplianceOutputBase):
    """This class represents the GCP CCC compliance output."""

    @property
    def model(self) -> Type[CCC_GCPModel]:
        """Returns the specific CCC_GCPModel.

        Returns:
            Type[CCC_GCPModel]: The model class for compliance serialization.
        """
        return CCC_GCPModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "ProjectId": "",
                "Location": "",
            }
        return {
            "ProjectId": finding.account_uid,
            "Location": finding.region,
        }
