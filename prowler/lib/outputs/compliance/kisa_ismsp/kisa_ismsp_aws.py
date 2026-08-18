from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.kisa_ismsp.models import AWSKISAISMSPModel
from prowler.lib.outputs.finding import Finding
from prowler.lib.check.compliance_models import Compliance_Requirement


class AWSKISAISMSP(ComplianceOutputBase):
    """
    This class represents the AWS KISA-ISMS-P compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS KISA-ISMS-P compliance format.
    """


    @property
    def model(self) -> Type[AWSKISAISMSPModel]:
        """Returns the specific AWSKISAISMSPModel."""
        return AWSKISAISMSPModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "AccountId": "",
                "Region": "",
            }
        return {
            "AccountId": finding.account_uid,
            "Region": finding.region,
        }

    def get_framework_specific_fields(self, requirement: Compliance_Requirement) -> dict[str, str]:
        """Returns framework-specific fields for the compliance output."""
        return {
            "Requirements_Name": requirement.Name,
        }

