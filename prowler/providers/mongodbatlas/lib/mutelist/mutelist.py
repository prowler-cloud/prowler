from prowler.lib.check.models import CheckReportMongoDBAtlas
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class MongoDBAtlasMutelist(Mutelist):
    """MongoDB Atlas Mutelist class"""

    def is_finding_muted(
        self,
        finding: CheckReportMongoDBAtlas,
        account_name: str,
    ) -> bool:
        """
        Check if a finding is muted in the MongoDB Atlas mutelist.

        Args:
            finding: The CheckReportMongoDBAtlas finding
            account_name: The account/project name

        Returns:
            bool: True if the finding is muted, False otherwise
        """
        return self.is_muted(
            account_name,
            finding.check_metadata.CheckID,
            "*",  # MongoDB Atlas doesn't have regions in the same way as AWS
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
