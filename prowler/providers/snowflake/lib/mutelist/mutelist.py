from prowler.lib.check.models import CheckReportSnowflake
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class SnowflakeMutelist(Mutelist):
    """Snowflake-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportSnowflake,
        account: str,
    ) -> bool:
        """
        Check if a Snowflake finding is muted.

        Args:
            finding: CheckReportSnowflake instance containing check metadata, resource info, and tags.
            account: Snowflake account identifier.

        Returns:
            True if the finding is muted, False otherwise.
        """
        return self.is_muted(
            account,
            finding.check_metadata.CheckID,
            finding.region or "global",
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
