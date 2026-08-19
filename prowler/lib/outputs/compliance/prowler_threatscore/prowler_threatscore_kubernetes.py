from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreKubernetesModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreKubernetes(ComplianceOutputBase):
    """This class represents the Kubernetes Prowler ThreatScore compliance output."""


    @property
    def model(self) -> Type[ProwlerThreatScoreKubernetesModel]:
        """Returns the specific ProwlerThreatScoreKubernetesModel."""
        return ProwlerThreatScoreKubernetesModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "Context": "",
                "Namespace": "",
            }
        return {
            "Context": "" if finding.account_name is None else finding.account_name,
            "Namespace": finding.region,
        }
