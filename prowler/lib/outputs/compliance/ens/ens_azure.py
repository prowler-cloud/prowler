from typing import Type, Optional
from prowler.config.config import timestamp
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.ens.models import AzureENSModel
from prowler.lib.outputs.finding import Finding


class AzureENS(ComplianceOutputBase):
    """This class represents the Azure ENS compliance output."""

    @property
    def model(self) -> Type[AzureENSModel]:
        """Returns the specific AzureENSModel.

        Returns:
            Type[AzureENSModel]: The AzureENSModel class.
        """
        return AzureENSModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict[str, str]:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None for manual checks.

        Returns:
            dict[str, str]: A dictionary containing SubscriptionId and Location.
        """
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_name or "",
            "Location": finding.region or "",
        }

