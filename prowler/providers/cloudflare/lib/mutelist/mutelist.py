from prowler.lib.check.models import CheckReportCloudflare
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class CloudflareMutelist(Mutelist):
    """Cloudflare-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportCloudflare,
        account_id: str,
    ) -> bool:
        return self.is_muted(
            account_id,
            finding.check_metadata.CheckID,
            "global",  # Cloudflare is a global service
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
