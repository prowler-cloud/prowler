from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.athena.athena_client import athena_client


class athena_workgroup_encryption(Check):
    """Check if there are Athena workgroups not encrypting query results"""

    def execute(self):
        """Execute the athena_workgroup_encryption check"""
        findings = []
        for workgroup in athena_client.workgroups.values():
            # Only check for enabled and used workgroups (has recent queries)
            if (
                workgroup.state == "ENABLED" and workgroup.queries
            ) or athena_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.region = workgroup.region
                report.resource_id = workgroup.name
                report.resource_arn = workgroup.arn
                report.resource_tags = workgroup.tags

                if workgroup.encryption_configuration.encrypted:
                    report.status = "PASS"
                    report.status_extended = f"Athena WorkGroup {workgroup.name} encrypts the query results using {workgroup.encryption_configuration.encryption_option}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Athena WorkGroup {workgroup.name} does not encrypt the query results."

                findings.append(report)

        return findings
