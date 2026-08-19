from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.iso27001.models import AWSISO27001Model
from prowler.lib.outputs.finding import Finding
from prowler.lib.check.compliance_models import Compliance_Requirement


class AWSISO27001(ComplianceOutputBase):
    """This class represents the AWS ISO 27001 compliance output."""


    @property
    def model(self) -> Type[AWSISO27001Model]:
        """Returns the specific AWSISO27001Model."""
        return AWSISO27001Model

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

