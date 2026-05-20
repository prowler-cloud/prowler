from prowler.lib.check.models import CheckReportScaleway
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class ScalewayMutelist(Mutelist):
    """Scaleway-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportScaleway,
        organization_id: str,
    ) -> bool:
        return self.is_muted(
            organization_id,
            finding.check_metadata.CheckID,
            finding.region or "global",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
