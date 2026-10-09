from prowler.lib.check.models import CheckReportFly
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class FlyMutelist(Mutelist):
    """Fly.io-specific mutelist helper."""

    def is_finding_muted(
        self,
        finding: CheckReportFly,
        org_slug: str,
    ) -> bool:
        """Evaluate a finding against the selected organization's muting rules.

        Args:
            finding: Fly.io finding with check, resource, region, and tag metadata.
            org_slug: Organization slug used as the mutelist account key.

        Returns:
            True when the finding matches an applicable mutelist rule.
        """
        return self.is_muted(
            org_slug,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id or finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
