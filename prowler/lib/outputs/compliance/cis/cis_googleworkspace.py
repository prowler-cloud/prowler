from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import GoogleWorkspaceCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GoogleWorkspaceCIS(ComplianceOutputBase):
    """This class represents the Google Workspace CIS compliance output."""

    @property
    def model(self) -> Type[GoogleWorkspaceCISModel]:
        """Returns the specific GoogleWorkspaceCISModel.

        Returns:
            Type[GoogleWorkspaceCISModel]: The model class for compliance serialization.
        """
        return GoogleWorkspaceCISModel

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
