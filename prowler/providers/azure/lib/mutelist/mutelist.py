from prowler.lib.check.models import Check_Report_Azure
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class AzureMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Check_Report_Azure,
        subscription_id: str,
    ) -> bool:
        return self.is_muted(
            subscription_id,  # support Azure Subscription ID in mutelist
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        ) or self.is_muted(
            finding.subscription,  # support Azure Subscription Name in mutelist
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
