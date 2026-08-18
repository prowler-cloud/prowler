from typing import Type, Optional
from prowler.config.config import timestamp
from prowler.lib.check.compliance_config_eval import (
    apply_config_status,
    build_requirement_config_status,
)
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import AWSCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding


class AWSCIS(ComplianceOutputBase):
    """
    This class represents the AWS CIS compliance output.
    """

    @property
    def model(self) -> Type[AWSCISModel]:
        """Returns the specific AWSCISModel."""
        return AWSCISModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "AccountId": "",
                "Region": "",
            }
        return {
            "AccountId": finding.account_uid,
            "Region": finding.region,
        }
