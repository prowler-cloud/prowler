from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_secret_rotated_periodically(Check):
    """Check if AWS Secret Manager secrets are rotated periodically.

    This class checks if each secret in AWS Secret Manager has been rotated periodically
    the maximum number of days allowed could be configured in the audit_config file as max_days_secret_unrotated.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute secretsmanager_secret_rotated_periodically check.

        Iterate over all secrets in AWS Secret Manager and check if each secret has been rotated in the past
        max_days_secret_unrotated days.

        Returns:
            List of reports objects for each secret in AWS Secret Manager.
        """
        findings = []
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.region = secret.region
            report.resource_tags = secret.tags
            report.status = "PASS"
            report.status_extended = f"Secret {secret.name} was last rotated on {secret.last_rotated_date.strftime('%B %d, %Y')}."

            if secret.last_rotated_date == datetime.min.replace(tzinfo=timezone.utc):
                report.status = "FAIL"
                report.status_extended = f"Secret {secret.name} has never been rotated."
            else:
                days_since_last_rotation = (
                    datetime.now(timezone.utc) - secret.last_rotated_date
                ).days

                if days_since_last_rotation > secretsmanager_client.audit_config.get(
                    "max_days_secret_unrotated", 90
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Secret {secret.name} has not been rotated in {days_since_last_rotation} days, which is more than the maximum allowed of {secretsmanager_client.audit_config.get('max_days_secret_unrotated', 90)} days."

            findings.append(report)

        return findings
