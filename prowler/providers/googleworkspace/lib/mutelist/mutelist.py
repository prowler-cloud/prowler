from prowler.lib.check.models import CheckReportGoogleWorkspace
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class GoogleWorkspaceMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: CheckReportGoogleWorkspace,
    ) -> bool:
        return self.is_muted(
            finding.customer_id,
            finding.check_metadata.CheckID,
            finding.location,  # Google Workspace resources are typically "global"
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
