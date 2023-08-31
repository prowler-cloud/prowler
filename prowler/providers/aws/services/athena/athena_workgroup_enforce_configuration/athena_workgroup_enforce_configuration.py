from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.athena.athena_client import athena_client


class athena_workgroup_enforce_configuration(Check):
    """Check if there are Athena workgroups not encrypting query results"""

    def execute(self):
        """Execute the athena_workgroup_enforce_configuration check"""
        findings = []
        for workgroup in athena_client.workgroups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = workgroup.region
            report.resource_id = workgroup.name
            report.resource_arn = workgroup.arn
            report.resource_tags = workgroup.tags

            if workgroup.enforce_workgroup_configuration:
                report.status = "PASS"
                report.status_extended = f"Athena WorkGroup {workgroup.name} enforces the workgroup configuration, so it cannot be overridden by the client-side settings."
            else:
                report.status = "FAIL"
                report.status_extended = f"Athena WorkGroup {workgroup.name} does not enforce the workgroup configuration, so it can be overridden by the client-side settings."

            findings.append(report)

        return findings
