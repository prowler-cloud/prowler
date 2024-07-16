from typing import Any

from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class GCPMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Any,
    ) -> bool:
        return self.is_muted(
            finding.project_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_tags(finding.resource_tags),
        )
