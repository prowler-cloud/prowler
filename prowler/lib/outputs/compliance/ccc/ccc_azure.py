from typing import Optional, Type
from prowler.lib.outputs.compliance.ccc.models import CCC_AzureModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class CCC_Azure(ComplianceOutputBase):
    """This class represents the Azure CCC compliance output."""

    @property
    def model(self) -> Type[CCC_AzureModel]:
        """Returns the specific CCC_AzureModel.

        Returns:
            Type[CCC_AzureModel]: The model class for compliance serialization.
        """
        return CCC_AzureModel

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
