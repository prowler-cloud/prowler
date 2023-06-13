from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.drs.drs_client import drs_client


class drs_job_exist(Check):
    def execute(self):
        findings = []
        for drs in drs_client.drs_services:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "DRS is not enabled for this region."
            report.region = drs.region
            report.resource_tags = []
            report.resource_arn = drs_client.audited_account_arn
            report.resource_id = drs_client.audited_account
            if drs.status == "ENABLED":
                report.status_extended = "DRS is enabled for this region without jobs."
                if drs.jobs:
                    report.status = "PASS"
                    report.status_extended = "DRS is enabled for this region with jobs."

            findings.append(report)

        return findings
