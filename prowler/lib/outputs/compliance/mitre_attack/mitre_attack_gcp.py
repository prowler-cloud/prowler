from typing import Optional, Type

from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    MitreAttackOutputBase,
)
from prowler.lib.outputs.compliance.mitre_attack.models import GCPMitreAttackModel
from prowler.lib.outputs.finding import Finding


class GCPMitreAttack(MitreAttackOutputBase):
    """This class represents the GCP MITRE ATT&CK compliance output."""

    @property
    def model(self) -> Type[GCPMitreAttackModel]:
        """Returns the specific GCPMitreAttackModel.

        Returns:
            Type[GCPMitreAttackModel]: The model class for compliance serialization.
        """
        return GCPMitreAttackModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "ProjectId": "",
                "Location": "",
            }
        return {
            "ProjectId": finding.account_uid,
            "Location": finding.region,
        }


