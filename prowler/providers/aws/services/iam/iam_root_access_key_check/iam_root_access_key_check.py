from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_access_key_check(Check):
    def execute(self):
        findings = []

        report = Check_Report_AWS(self.metadata())
        report.region = "global"
        report.resource_id = "root_account"
        report.resource_arn = "arn:aws:iam::root"
        report.resource_tags = {}  # Root account generally has no tags

        # Check if root account has access keys
        if iam_client.__check_root_access_keys__():
            report.status = "FAIL"
            report.status_extended = "Root account has access keys enabled."
        else:
            report.status = "PASS"
            report.status_extended = "Root account does not have access keys."

        findings.append(report)
        return findings
