from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.ens.models import GCPENSModel
from prowler.lib.outputs.finding import Finding


class GCPENS(ComplianceOutputBase):
    """This class represents the GCP ENS compliance output."""


    @property
    def model(self) -> Type[GCPENSModel]:
        """Returns the specific GCPENSModel."""
        return GCPENSModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict[str, str]:
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
