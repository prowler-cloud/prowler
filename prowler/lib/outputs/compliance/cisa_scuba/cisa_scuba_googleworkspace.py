from typing import Optional, Type

from prowler.lib.outputs.compliance.cisa_scuba.models import (
    GoogleWorkspaceCISASCuBAModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GoogleWorkspaceCISASCuBA(ComplianceOutputBase):
    """This class represents the Google Workspace CISA SCuBA compliance output."""

    @property
    def model(self) -> Type[GoogleWorkspaceCISASCuBAModel]:
        """Returns the specific GoogleWorkspaceCISASCuBAModel.

        Returns:
            Type[GoogleWorkspaceCISASCuBAModel]: The model class for compliance serialization.
        """
        return GoogleWorkspaceCISASCuBAModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "Domain": "",
            }
        return {
            "Domain": finding.account_name or "",
        }
