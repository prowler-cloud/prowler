"""E2E Cloud mutelist support for suppressing findings."""

from prowler.lib.check.models import CheckReportE2e
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class E2eMutelist(Mutelist):
    """Mutelist implementation for E2E Cloud check findings."""

    def is_finding_muted(self, **kwargs) -> bool:
        """Determine whether an E2E Cloud finding is muted.

        Args:
            **kwargs: Keyword arguments; must include ``finding``.

        Returns:
            True if the finding matches a mutelist entry, otherwise False.
        """
        finding: CheckReportE2e = kwargs["finding"]
        return self.is_muted(
            finding.resource_id,
            finding.check_metadata.CheckID,
            finding.location,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
