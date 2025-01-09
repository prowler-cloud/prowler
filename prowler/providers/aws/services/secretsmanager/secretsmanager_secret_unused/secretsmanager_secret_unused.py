from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_secret_unused(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.region = secret.region
            report.resource_tags = secret.tags
            report.status = "PASS"
            report.status_extended = f"Secret {secret.name} has been accessed recently, last accessed on {secret.last_accessed_date.strftime('%B %d, %Y')}."

            if (datetime.now(timezone.utc) - secret.last_accessed_date) > timedelta(
                days=secretsmanager_client.audit_config.get(
                    "max_days_secret_unused", 90
                )
            ):
                report.status = "FAIL"
                if secret.last_accessed_date == datetime.min.replace(
                    tzinfo=timezone.utc
                ):
                    report.status_extended = (
                        f"Secret {secret.name} has never been accessed."
                    )
                else:
                    report.status_extended = f"Secret {secret.name} has not been accessed since {secret.last_accessed_date.strftime('%B %d, %Y')}, you should review if it is still needed."

            findings.append(report)

        return findings
