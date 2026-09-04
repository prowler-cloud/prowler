from typing import Optional, Type
from prowler.lib.outputs.compliance.ccc.models import CCC_AWSModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class CCC_AWS(ComplianceOutputBase):
    """This class represents the AWS CCC compliance output."""

    @property
    def model(self) -> Type[CCC_AWSModel]:
        """Returns the specific CCC_AWSModel.

        Returns:
            Type[CCC_AWSModel]: The model class for compliance serialization.
        """
        return CCC_AWSModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
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
