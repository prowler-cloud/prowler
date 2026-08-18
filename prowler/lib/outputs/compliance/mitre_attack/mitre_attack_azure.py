from typing import Optional, Type

from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    MitreAttackOutputBase,
)
from prowler.lib.outputs.compliance.mitre_attack.models import AzureMitreAttackModel
from prowler.lib.outputs.finding import Finding


class AzureMitreAttack(MitreAttackOutputBase):
    """This class represents the Azure MITRE ATT&CK compliance output."""

    @property
    def model(self) -> Type[AzureMitreAttackModel]:
        """Returns the specific AzureMitreAttackModel.

        Returns:
            Type[AzureMitreAttackModel]: The AzureMitreAttackModel class.
        """
        return AzureMitreAttackModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None for manual checks.

        Returns:
            dict: A dictionary containing SubscriptionId and Location.
        """
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_uid,
            "Location": finding.region,
        }


