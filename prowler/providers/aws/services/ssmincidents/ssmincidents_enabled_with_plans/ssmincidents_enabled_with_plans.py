from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssmincidents.ssmincidents_client import (
    ssmincidents_client,
)


class ssmincidents_enabled_with_plans(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "No SSM Incidents replication set exists."
        report.resource_arn = f"arn:{ssmincidents_client.audited_partition}:ssm-incidents:{ssmincidents_client.region}:{ssmincidents_client.audited_account}:replication-set"
        report.resource_id = ssmincidents_client.audited_account
        report.region = ssmincidents_client.region
        if ssmincidents_client.replication_set:
            report.resource_arn = ssmincidents_client.replication_set[0].arn
            report.resource_tags = []  # Not supported for replication sets
            report.status_extended = f"SSM Incidents replication set {ssmincidents_client.replication_set[0].arn} exists but not ACTIVE."
            if ssmincidents_client.replication_set[0].status == "ACTIVE":
                report.status_extended = f"SSM Incidents replication set {ssmincidents_client.replication_set[0].arn} is ACTIVE but no response plans exist."
                if ssmincidents_client.response_plans:
                    report.status = "PASS"
                    report.status_extended = f"SSM Incidents replication set {ssmincidents_client.replication_set[0].arn} is ACTIVE and has response plans."

        findings.append(report)

        return findings
