from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cisa_scuba.models import (
    GoogleWorkspaceCISASCuBAModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GoogleWorkspaceCISASCuBA(ComplianceOutputBase):
    """This class represents the Google Workspace CISA SCuBA compliance output."""


    @property
    def model(self) -> Type[GoogleWorkspaceCISASCuBAModel]:
        """Returns the specific GoogleWorkspaceCISASCuBAModel."""
        return GoogleWorkspaceCISASCuBAModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "Domain": "",
            }
        return {
            "Domain": finding.account_name if finding and finding.account_name else 'unknown',
        }
