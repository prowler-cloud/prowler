from prowler.lib.check.models import CheckReportLovable
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class LovableMutelist(Mutelist):
    """Lovable-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportLovable,
        workspace_id: str,
    ) -> bool:
        return self.is_muted(
            workspace_id,
            finding.check_metadata.CheckID,
            "global",  # Lovable is global
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
