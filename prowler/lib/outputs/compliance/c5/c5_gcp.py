from typing import Optional, Type
from prowler.lib.outputs.compliance.c5.models import GCPC5Model
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GCPC5(ComplianceOutputBase):
    """This class represents the GCP C5 compliance output."""

    @property
    def model(self) -> Type[GCPC5Model]:
        """Returns the specific GCPC5Model.

        Returns:
            Type[GCPC5Model]: The model class for compliance serialization.
        """
        return GCPC5Model

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
