from typing import Optional, Type

from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    MitreAttackOutputBase,
)
from prowler.lib.outputs.compliance.mitre_attack.models import AWSMitreAttackModel
from prowler.lib.outputs.finding import Finding


class AWSMitreAttack(MitreAttackOutputBase):
    """This class represents the AWS MITRE ATT&CK compliance output."""

    @property
    def model(self) -> Type[AWSMitreAttackModel]:
        """Returns the specific AWSMitreAttackModel.

        Returns:
            Type[AWSMitreAttackModel]: The model class for compliance serialization.
        """
        return AWSMitreAttackModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "AccountId": "",
                "Region": "",
            }
        return {
            "AccountId": finding.account_uid,
            "Region": finding.region,
        }


