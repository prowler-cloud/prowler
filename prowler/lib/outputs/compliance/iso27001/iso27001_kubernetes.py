from typing import Optional, Type
from prowler.lib.check.compliance_models import Compliance_Requirement
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.iso27001.models import KubernetesISO27001Model
from prowler.lib.outputs.finding import Finding


class KubernetesISO27001(ComplianceOutputBase):
    """This class represents the Kubernetes ISO 27001 compliance output."""

    @property
    def model(self) -> Type[KubernetesISO27001Model]:
        """Returns the specific KubernetesISO27001Model.

        Returns:
            Type[KubernetesISO27001Model]: The model class for compliance serialization.
        """
        return KubernetesISO27001Model

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

    def get_framework_specific_fields(
        self, requirement: Compliance_Requirement
    ) -> dict[str, str]:
        """Returns the framework specific fields for the compliance output."""
        return {
            "Requirements_Name": requirement.Name or "",
        }
