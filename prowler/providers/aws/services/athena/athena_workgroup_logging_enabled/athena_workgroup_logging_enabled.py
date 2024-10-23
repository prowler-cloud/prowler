from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.athena.athena_client import athena_client


class athena_workgroup_logging_enabled(Check):
    """Check if there are Athena workgroups with logging disabled."""

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the Athena workgroup logging enabled check.

        Iterates over all Athena workgroups and checks if is publishing logs to CloudWatch.

        Returns:
            List of reports object with the findings of each workgroup.
        """
        findings = []
        for workgroup in athena_client.workgroups.values():
            # Only check for enabled and used workgroups (has recent queries)
            if (
                workgroup.state == "ENABLED" and workgroup.queries
            ) or athena_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = workgroup.name
                report.resource_arn = workgroup.arn
                report.region = workgroup.region
                report.resource_tags = workgroup.tags
                report.status = "PASS"
                report.status_extended = (
                    f"Athena WorkGroup {workgroup.name} has CloudWatch logging enabled."
                )

                if not workgroup.cloudwatch_logging:
                    report.status = "FAIL"
                    report.status_extended = f"Athena WorkGroup {workgroup.name} does not have CloudWatch logging enabled."

                findings.append(report)

        return findings
