from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_check_if_secure_strings_is_in_use(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        if any(
            [parameter["Type"] == "SecureString" for parameter in ssm_client.parameters]
        ):
            report.status = "PASS"
            report.status_extended = "SSM secure strings is in use."
        else:
            report.status = "FAIL"
            report.status_extended = "SSm secure strings is not in use."

        findings.append(report)

        return findings
