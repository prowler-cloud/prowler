from prowler.lib.check.models import CheckReportHuaweiCloud
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class HuaweiCloudMutelist(Mutelist):
    """Huawei Cloud-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportHuaweiCloud,
        account_id: str,
    ) -> bool:
        """
        Check if a Huawei Cloud finding is muted.

        Args:
            finding: CheckReportHuaweiCloud instance containing check metadata,
                region, resource info, and tags.
            account_id: The Huawei Cloud account ID to use for mutelist evaluation.

        Returns:
            True if the finding is muted, False otherwise.
        """
        return self.is_muted(
            account_id,
            finding.check_metadata.CheckID,
            finding.region or "",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
