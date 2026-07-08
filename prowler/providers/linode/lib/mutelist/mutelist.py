from prowler.lib.check.models import CheckReportLinode
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class LinodeMutelist(Mutelist):
    """Linode-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportLinode,
        account_id: str,
    ) -> bool:
        """
        Check if a Linode finding is muted.

        Args:
            finding: CheckReportLinode instance containing check metadata, region, resource info, and tags.
            account_id: Linode account identifier.

        Returns:
            True if the finding is muted, False otherwise.
        """
        return self.is_muted(
            account_id,
            finding.check_metadata.CheckID,
            finding.region or "global",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
