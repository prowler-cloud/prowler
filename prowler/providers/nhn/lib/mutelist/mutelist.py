from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.check.models import Check_Report

class NHNMutelist(Mutelist):
    def is_finding_muted(self, finding: Check_Report) -> bool:
        return self.is_muted(
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
        )
