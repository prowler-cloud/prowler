from typing import Optional, Type

from prowler.lib.check.compliance_models import Compliance_Requirement
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.okta_idaas_stig.models import OktaIDaaSSTIGModel
from prowler.lib.outputs.finding import Finding


class OktaIDaaSSTIG(ComplianceOutputBase):
    """This class represents the Okta IDaaS STIG compliance output."""

    @property
    def model(self) -> Type[OktaIDaaSSTIGModel]:
        """Returns the specific OktaIDaaSSTIGModel.

        Returns:
            Type[OktaIDaaSSTIGModel]: The model class for compliance serialization.
        """
        return OktaIDaaSSTIGModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "OrganizationDomain": "",
            }
        return {
            "OrganizationDomain": finding.account_name or "",
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

