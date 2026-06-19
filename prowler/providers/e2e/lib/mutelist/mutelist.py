from prowler.lib.check.models import CheckReportE2e
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class E2eMutelist(Mutelist):
    def is_finding_muted(self, finding: CheckReportE2e) -> bool:
        return self.is_muted(
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
