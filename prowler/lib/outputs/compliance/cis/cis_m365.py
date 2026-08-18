from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import M365CISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class M365CIS(ComplianceOutputBase):
    """
    This class represents the M365 CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into M365 CIS compliance format.
    """


    @property
    def model(self) -> Type[M365CISModel]:
        """Returns the specific M365CISModel."""
        return M365CISModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "TenantId": "",
                "Location": "",
            }
        return {
            "TenantId": finding.account_uid,
            "Location": finding.region,
        }
