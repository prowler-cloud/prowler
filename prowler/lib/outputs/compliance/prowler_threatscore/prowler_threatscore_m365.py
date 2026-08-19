from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreM365Model,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreM365(ComplianceOutputBase):
    """This class represents the M365 Prowler ThreatScore compliance output."""


    @property
    def model(self) -> Type[ProwlerThreatScoreM365Model]:
        """Returns the specific ProwlerThreatScoreM365Model."""
        return ProwlerThreatScoreM365Model

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "TenantId": "",
                "Location": "",
            }
        return {
            "TenantId": finding.account_uid,
            "Location": finding.region,
        }
