from typing import Optional, Type
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreAzureModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreAzure(ComplianceOutputBase):
    """This class represents the Azure Prowler ThreatScore compliance output."""

    @property
    def model(self) -> Type[ProwlerThreatScoreAzureModel]:
        """Returns the specific ProwlerThreatScoreAzureModel.

        Returns:
            Type[ProwlerThreatScoreAzureModel]: The model class for compliance serialization.
        """
        return ProwlerThreatScoreAzureModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_uid,
            "Location": finding.region,
        }
