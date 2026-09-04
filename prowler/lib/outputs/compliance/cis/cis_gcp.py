from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import GCPCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GCPCIS(ComplianceOutputBase):
    """This class represents the GCP CIS compliance output."""

    @property
    def model(self) -> Type[GCPCISModel]:
        """Returns the specific GCPCISModel.

        Returns:
            Type[GCPCISModel]: The model class for compliance serialization.
        """
        return GCPCISModel

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
