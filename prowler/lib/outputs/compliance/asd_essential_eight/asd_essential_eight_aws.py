from typing import Optional, Type
from prowler.lib.outputs.compliance.asd_essential_eight.models import (
    ASDEssentialEightAWSModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class ASDEssentialEightAWS(ComplianceOutputBase):
    """This class represents the AWS ASD Essential Eight compliance output."""

    @property
    def model(self) -> Type[ASDEssentialEightAWSModel]:
        """Returns the specific ASDEssentialEightAWSModel.

        Returns:
            Type[ASDEssentialEightAWSModel]: The model class for compliance serialization.
        """
        return ASDEssentialEightAWSModel

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
