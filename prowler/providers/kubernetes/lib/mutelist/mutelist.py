from prowler.lib.check.models import Check_Report_Kubernetes
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class KubernetesMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Check_Report_Kubernetes,
        cluster: str,
    ) -> bool:
        return self.is_muted(
            cluster,
            finding.check_metadata.CheckID,
            finding.namespace,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
