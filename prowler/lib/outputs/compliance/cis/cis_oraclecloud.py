from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import OracleCloudCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class OracleCloudCIS(ComplianceOutputBase):
    """This class represents the Oracle Cloud CIS compliance output."""

    @property
    def model(self) -> Type[OracleCloudCISModel]:
        """Returns the specific OracleCloudCISModel.

        Returns:
            Type[OracleCloudCISModel]: The model class for compliance serialization.
        """
        return OracleCloudCISModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None.

        Returns:
            dict: A dictionary containing provider identity fields.
        """
        if finding is None:
            return {
                "TenancyId": "",
                "Region": "",
            }
        return {
            "TenancyId": finding.account_uid,
            "Region": finding.region,
        }
