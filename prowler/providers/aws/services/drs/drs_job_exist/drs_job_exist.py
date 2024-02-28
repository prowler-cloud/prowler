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
            report.resource_arn = drs_client.recovery_job_arn_template
            report.resource_id = drs_client.audited_account
            if drs.status == "ENABLED":
                report.status_extended = "DRS is enabled for this region without jobs."
                if drs.jobs:
                    report.status = "PASS"
                    report.status_extended = "DRS is enabled for this region with jobs."

            if report.status == "FAIL" and (
                drs_client.audit_config.get("allowlist_non_default_regions", False)
                and not drs.region == drs_client.region
            ):
                report.status = "WARNING"

            findings.append(report)

        return findings
