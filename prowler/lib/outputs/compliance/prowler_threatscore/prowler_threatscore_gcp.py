from typing import Optional, Type
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreGCPModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreGCP(ComplianceOutputBase):
    """This class represents the GCP Prowler ThreatScore compliance output."""

    @property
    def model(self) -> Type[ProwlerThreatScoreGCPModel]:
        """Returns the specific ProwlerThreatScoreGCPModel.

        Returns:
            Type[ProwlerThreatScoreGCPModel]: The model class for compliance serialization.
        """
        return ProwlerThreatScoreGCPModel

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
