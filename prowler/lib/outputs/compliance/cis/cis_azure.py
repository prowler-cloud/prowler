from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import AzureCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AzureCIS(ComplianceOutputBase):
    """This class represents the Azure CIS compliance output."""

    @property
    def model(self) -> Type[AzureCISModel]:
        """Returns the specific AzureCISModel.

        Returns:
            Type[AzureCISModel]: The model class for compliance serialization.
        """
        return AzureCISModel

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
