from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_check_if_service_is_in_use(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        if len(secretsmanager_client.secrets) > 0:
            report.status = "PASS"
            report.status_extended = "SecretsManager service is in use."
        else:
            report.status = "FAIL"
            report.status_extended = "SecretsManager service is not in use."

        findings.append(report)

        return findings
