from prowler.lib.check.models import CheckReportOkta
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class OktaMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: CheckReportOkta,
        org_url: str,
    ) -> bool:
        return self.is_muted(
            org_url,
            finding.check_metadata.CheckID,
            "*",
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
