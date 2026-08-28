from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import KubernetesCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class KubernetesCIS(ComplianceOutputBase):
    """This class represents the Kubernetes CIS compliance output."""

    @property
    def model(self) -> Type[KubernetesCISModel]:
        """Returns the specific KubernetesCISModel.

        Returns:
            Type[KubernetesCISModel]: The model class for compliance serialization.
        """
        return KubernetesCISModel

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
