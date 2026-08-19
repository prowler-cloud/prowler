from prowler.lib.check.models import CheckReportSupabase
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class SupabaseMutelist(Mutelist):
    """Supabase-specific mutelist helper."""

    def is_finding_muted(self, finding: CheckReportSupabase) -> bool:
        return self.is_muted(
            finding.organization_slug,
            finding.check_metadata.CheckID,
            "global",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
