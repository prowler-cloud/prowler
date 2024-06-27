from typing import Any

from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class MutelistKubernetes(Mutelist):
    def is_finding_muted(
        self,
        finding: Any,
        cluster: str,
        check_id: str,
    ) -> bool:
        return self.is_muted(
            self._mutelist,
            cluster,
            check_id,
            finding.namespace,
            finding.resource_name,
            unroll_tags(finding.resource_tags),
        )
