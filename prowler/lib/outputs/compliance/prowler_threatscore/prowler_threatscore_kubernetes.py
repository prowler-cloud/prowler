from typing import Optional, Type
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreKubernetesModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreKubernetes(ComplianceOutputBase):
    """This class represents the Kubernetes Prowler ThreatScore compliance output."""

    @property
    def model(self) -> Type[ProwlerThreatScoreKubernetesModel]:
        """Returns the specific ProwlerThreatScoreKubernetesModel.

        Returns:
            Type[ProwlerThreatScoreKubernetesModel]: The model class for compliance serialization.
        """
        return ProwlerThreatScoreKubernetesModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "Context": "",
                "Cluster": "",
                "Namespace": "",
            }
        return {
            "Context": finding.account_name or "",
            "Cluster": finding.account_uid or "",
            "Namespace": finding.region,
        }
