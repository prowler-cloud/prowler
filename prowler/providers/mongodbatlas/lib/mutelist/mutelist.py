from prowler.lib.check.models import CheckReportMongoDBAtlas
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class MongoDBAtlasMutelist(Mutelist):
    """MongoDB Atlas Mutelist class"""

    def is_finding_muted(
        self,
        finding: CheckReportMongoDBAtlas,
        organization_id: str,
    ) -> bool:
        """
        Check if a finding is muted in the MongoDB Atlas mutelist.

        Args:
            finding: The CheckReportMongoDBAtlas finding
            organization_id: The organization/project id

        Returns:
            bool: True if the finding is muted, False otherwise
        """
        return self.is_muted(
            organization_id,
            finding.check_metadata.CheckID,
            finding.location,  # TODO: Study regions in MongoDB Atlas
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
