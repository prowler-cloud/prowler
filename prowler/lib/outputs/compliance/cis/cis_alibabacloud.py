from typing import Optional, Type
from prowler.lib.outputs.compliance.cis.models import AlibabaCloudCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class AlibabaCloudCIS(ComplianceOutputBase):
    """This class represents the Alibaba Cloud CIS compliance output."""

    @property
    def model(self) -> Type[AlibabaCloudCISModel]:
        """Returns the specific AlibabaCloudCISModel.

        Returns:
            Type[AlibabaCloudCISModel]: The model class for compliance serialization.
        """
        return AlibabaCloudCISModel

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
