from prowler.lib.check.models import CheckReportNHN
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class NHNMutelist(Mutelist):
    def is_finding_muted(self, finding: CheckReportNHN) -> bool:
        return self.is_muted(
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
