from prowler.lib.check.models import CheckReportVercel
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class VercelMutelist(Mutelist):
    """Vercel-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportVercel,
        team_id: str,
    ) -> bool:
        return self.is_muted(
            team_id,
            finding.check_metadata.CheckID,
            "global",  # Vercel is a global service
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
