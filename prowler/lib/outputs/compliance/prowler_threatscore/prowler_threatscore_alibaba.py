from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreAlibabaModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreAlibaba(ComplianceOutputBase):
    """This class represents the Alibaba Cloud Prowler ThreatScore compliance output."""


    @property
    def model(self) -> Type[ProwlerThreatScoreAlibabaModel]:
        """Returns the specific ProwlerThreatScoreAlibabaModel."""
        return ProwlerThreatScoreAlibabaModel

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
