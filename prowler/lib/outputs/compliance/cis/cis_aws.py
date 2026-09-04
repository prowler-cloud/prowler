from typing import Optional, Type

from prowler.lib.outputs.compliance.cis.models import AWSCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AWSCIS(ComplianceOutputBase):
    """This class represents the AWS CIS compliance output."""

    @property
    def model(self) -> Type[AWSCISModel]:
        """Returns the specific AWSCISModel.

        Returns:
            Type[AWSCISModel]: The model class for compliance serialization.
        """
        return AWSCISModel

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
