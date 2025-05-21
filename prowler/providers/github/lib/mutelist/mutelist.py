from prowler.lib.check.models import CheckReportGithub
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class GithubMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: CheckReportGithub,
        account_name: str,
    ) -> bool:
        return self.is_muted(
            account_name,
            finding.check_metadata.CheckID,
            "*",  # TODO: Study regions in GitHub
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
