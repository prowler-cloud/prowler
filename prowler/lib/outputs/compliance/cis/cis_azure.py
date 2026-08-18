from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import AzureCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AzureCIS(ComplianceOutputBase):
    """
    This class represents the Azure CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure CIS compliance format.
    """


    @property
    def model(self) -> Type[AzureCISModel]:
        """Returns the specific AzureCISModel."""
        return AzureCISModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_uid,
            "Location": finding.region,
        }
