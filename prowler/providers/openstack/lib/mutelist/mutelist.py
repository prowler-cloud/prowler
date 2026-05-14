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
        # Try matching with both resource_id and resource_name for better UX
        # Users can specify either the UUID or the friendly name in the mutelist
        muted_by_id = self.is_muted(
            project_id,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
        muted_by_name = self.is_muted(
            project_id,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
        return muted_by_id or muted_by_name
