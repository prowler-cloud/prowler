from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.okta_idaas_stig.models import OktaIDaaSSTIGModel
from prowler.lib.outputs.finding import Finding
from prowler.lib.check.compliance_models import Compliance_Requirement


class OktaIDaaSSTIG(ComplianceOutputBase):
    """
    This class represents the Okta IDaaS STIG compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Okta IDaaS STIG compliance format.
    """


    @property
    def model(self) -> Type[OktaIDaaSSTIGModel]:
        """Returns the specific OktaIDaaSSTIGModel."""
        return OktaIDaaSSTIGModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "OrganizationDomain": "",
            }
        return {
            "OrganizationDomain": "" if finding.account_name is None else finding.account_name,
        }

    def get_framework_specific_fields(self, requirement: Compliance_Requirement) -> dict[str, str]:
        """Returns framework-specific fields for the compliance output."""
        return {
            "Requirements_Name": requirement.Name,
        }

