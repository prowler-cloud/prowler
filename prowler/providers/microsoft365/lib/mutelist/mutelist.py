from prowler.lib.check.models import CheckReportMicrosoft365
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class Microsoft365Mutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: CheckReportMicrosoft365,
    ) -> bool:
        return self.is_muted(
            finding.tenant_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
