from typing import Optional, Type
from prowler.lib.outputs.compliance.c5.models import AWSC5Model
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AWSC5(ComplianceOutputBase):
    """This class represents the AWS C5 compliance output."""

    @property
    def model(self) -> Type[AWSC5Model]:
        """Returns the specific AWSC5Model.

        Returns:
            Type[AWSC5Model]: The model class for compliance serialization.
        """
        return AWSC5Model

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
