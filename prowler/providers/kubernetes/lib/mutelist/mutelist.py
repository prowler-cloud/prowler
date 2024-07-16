from typing import Any

from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class KubernetesMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Any,
        cluster: str,
    ) -> bool:
        return self.is_muted(
            cluster,
            finding.check_metadata.CheckID,
            finding.namespace,
            finding.resource_name,
            unroll_tags(finding.resource_tags),
        )
