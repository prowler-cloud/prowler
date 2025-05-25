from prowler.lib.check.models import Check_Report_IONOS
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags
from prowler.lib.logger import logger

class IonosMutelist(Mutelist):
    """
    Clase Mutelist para IONOS Cloud.
    """
    def is_finding_muted(
        self,
        finding: Check_Report_IONOS,
    ) -> bool:
        logger.debug(
            f"Checking if finding is muted: {finding.check_metadata.CheckID} for resource {finding.resource_name} in datacenter {finding.datacenter_id}"
        )
        return self.is_muted(
            finding.datacenter_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )