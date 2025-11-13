from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class StackITMutelist(Mutelist):
    def is_finding_muted(self, finding) -> bool:
        """
        Determines if a StackIT finding is muted based on mutelist rules.

        Args:
            finding: A CheckReportStackIT finding object

        Returns:
            bool: True if the finding is muted, False otherwise
        """
        return self.is_muted(
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
