from prowler.lib.check.models import CheckReportOpenStack
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class OpenStackMutelist(Mutelist):
    """Mutelist implementation for the OpenStack provider."""

    def is_finding_muted(
        self,
        finding: CheckReportOpenStack,
        project_id: str,
    ) -> bool:
        """Return True when the finding should be muted for the audited project."""
        return self.is_muted(
            project_id,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
