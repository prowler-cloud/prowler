from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.drs.drs_client import drs_client


class drs_jobs_exist(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "No DRS jobs exist."
        report.resource_id = "DRS"
        report.region = drs_client.region
        report.resource_tags = []
        report.resource_arn = ""
        if drs_client.drs_jobs:
            report.status = "PASS"
            report.status_extended = "DRS jobs exist."
            report.resource_tags = drs_client.drs_jobs[0].tags
            report.resource_arn = drs_client.drs_jobs[0].arn

        findings.append(report)

        return findings
