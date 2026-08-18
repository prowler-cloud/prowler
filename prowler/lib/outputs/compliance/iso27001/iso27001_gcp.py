from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.iso27001.models import GCPISO27001Model
from prowler.lib.outputs.finding import Finding


class GCPISO27001(ComplianceOutputBase):
    """
    This class represents the GCP ISO 27001 compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into GCP ISO 27001 compliance format.
    """


    @property
    def model(self) -> Type[GCPISO27001Model]:
        """Returns the specific GCPISO27001Model."""
        return GCPISO27001Model

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "ProjectId": "",
                "Location": "",
            }
        return {
            "ProjectId": finding.account_uid,
            "Location": finding.region,
        }

    def get_framework_specific_fields(self, requirement) -> dict:
        """Returns framework-specific fields for the compliance output."""
        return {
            "Requirements_Name": requirement.Name,
        }

