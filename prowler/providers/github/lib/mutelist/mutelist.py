from prowler.lib.check.models import Check_Report_Github
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class GithubMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Check_Report_Github,
    ) -> bool:
        return self.is_muted(
            finding.account_name,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
