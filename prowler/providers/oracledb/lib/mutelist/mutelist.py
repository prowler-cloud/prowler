from prowler.lib.check.models import CheckReportOracledb
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class OracledbMutelist(Mutelist):
    def is_finding_muted(
        self, finding: CheckReportOracledb, database_name: str
    ) -> bool:
        return self.is_muted(
            database_name,
            finding.check_metadata.CheckID,
            "*",
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
