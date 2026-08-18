from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.aws_well_architected.models import (
    AWSWellArchitectedModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AWSWellArchitected(ComplianceOutputBase):
    """
    This class represents the AWS Well-Architected compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS Well-Architected compliance format.
    """


    @property
    def model(self) -> Type[AWSWellArchitectedModel]:
        """Returns the specific AWSWellArchitectedModel."""
        return AWSWellArchitectedModel

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
