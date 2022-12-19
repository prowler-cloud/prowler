from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.emr.emr_client import emr_client


class emr_cluster_account_public_block_enabled(Check):
    def execute(self):
        findings = []
        for region in emr_client.block_public_access_configuration:
            report = Check_Report_AWS(self.metadata())
            report.region = region
            report.resource_id = emr_client.audited_account

            if emr_client.block_public_access_configuration[
                region
            ].block_public_security_group_rules:
                report.status = "PASS"
                report.status_extended = "EMR Account has Block Public Access enabled"
            else:
                report.status = "FAIL"
                report.status_extended = "EMR Account has Block Public Access disabled"

            findings.append(report)

        return findings
