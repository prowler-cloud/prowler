from prowler.lib.check.models import Check_Report_Azure
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class AzureMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Check_Report_Azure,
    ) -> bool:
        return self.is_muted(
            finding.subscription,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
