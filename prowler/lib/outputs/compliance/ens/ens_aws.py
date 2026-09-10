from typing import Optional, Type
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.ens.models import AWSENSModel
from prowler.lib.outputs.finding import Finding


class AWSENS(ComplianceOutputBase):
    """This class represents the AWS ENS compliance output."""

    @property
    def model(self) -> Type[AWSENSModel]:
        """Returns the specific AWSENSModel.

        Returns:
            Type[AWSENSModel]: The model class for compliance serialization.
        """
        return AWSENSModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict[str, str]:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict[str, str]: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "AccountId": "",
                "Region": "",
            }
        return {
            "AccountId": finding.account_uid,
            "Region": finding.region,
        }
