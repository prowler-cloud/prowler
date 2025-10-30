from prowler.lib.check.models import CheckReportCloudflare
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class CloudflareMutelist(Mutelist):
    """
    CloudflareMutelist class extends the Mutelist class to provide Cloudflare-specific mutelist functionality.

    This class is used to manage muted findings for Cloudflare resources.
    """

    def is_finding_muted(
        self,
        finding: CheckReportCloudflare,
        account_name: str,
    ) -> bool:
        """
        Check if a finding is muted based on the mutelist configuration.

        Args:
            finding (CheckReportCloudflare): The finding to check
            account_name (str): The Cloudflare account name

        Returns:
            bool: True if the finding is muted, False otherwise
        """
        return self.is_muted(
            account_name,
            finding.check_metadata.CheckID,
            "*",  # Cloudflare doesn't have regions
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
