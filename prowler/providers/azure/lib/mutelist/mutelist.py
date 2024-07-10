from typing import Any

from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class MutelistAzure(Mutelist):
    def is_finding_muted(
        self,
        finding: Any,
        subscription: str,
    ) -> bool:
        return self.is_muted(
            subscription,
            finding.check_metadata.CheckID,
            # TODO: add region to the findings when we add Azure Locations
            # finding.region,
            "",
            finding.resource_name,
            unroll_tags(finding.resource_tags),
        )
