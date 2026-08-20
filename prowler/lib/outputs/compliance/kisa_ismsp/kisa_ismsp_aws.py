from typing import Optional, Type

from prowler.lib.check.compliance_models import Compliance_Requirement
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.kisa_ismsp.models import AWSKISAISMSPModel
from prowler.lib.outputs.finding import Finding


class AWSKISAISMSP(ComplianceOutputBase):
    """This class represents the AWS KISA-ISMS-P compliance output."""

    @property
    def model(self) -> Type[AWSKISAISMSPModel]:
        """Returns the specific AWSKISAISMSPModel.

        Returns:
            Type[AWSKISAISMSPModel]: The model class for compliance serialization.
        """
        return AWSKISAISMSPModel

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

    def get_framework_specific_fields(
        self, requirement: Compliance_Requirement
    ) -> dict[str, str]:
        """Returns the framework specific fields for the compliance output.

        Args:
            requirement (Compliance_Requirement): The compliance requirement to extract fields from.

        Returns:
            dict[str, str]: A dictionary containing framework specific fields.
        """
        return {
            "Requirements_Name": requirement.Name or "",
        }

