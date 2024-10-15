from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_secret_rotated_successfully(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            if secret.rotation_enabled:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = secret.name
                report.resource_arn = secret.arn
                report.region = secret.region
                report.resource_tags = secret.tags
                report.status = "PASS"
                report.status_extended = f"Secret {secret.name} rotated successfully on {secret.last_rotation_date}, and next rotation is scheduled for {secret.next_rotation_date}."

                if (
                    secret.last_rotation_date.date() > datetime.now(timezone.utc).date()
                    and secret.next_rotation_date.date()
                    < datetime.now(timezone.utc).date()
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Secret {secret.name} has not be rotated successfully. Last rotation was on {secret.last_rotation_date}, and next rotation is scheduled for {secret.next_rotation_date}."

                findings.append(report)

        return findings
