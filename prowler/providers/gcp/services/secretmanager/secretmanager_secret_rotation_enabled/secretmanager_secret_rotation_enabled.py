from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.secretmanager.secretmanager_client import (
    secretmanager_client,
)

MAX_ROTATION_DAYS = 90


class secretmanager_secret_rotation_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for secret in secretmanager_client.secrets:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=secret,
                resource_id=secret.name,
                location=secret.location,
            )

            rotation_period_secs = None
            if secret.rotation_period:
                try:
                    rotation_period_secs = int(float(secret.rotation_period[:-1]))
                except (ValueError, IndexError):
                    rotation_period_secs = None

            rotation_days = (
                rotation_period_secs // 86400
                if rotation_period_secs is not None
                else None
            )

            rotation_overdue = False
            if rotation_days is not None and secret.next_rotation_time:
                try:
                    next_rotation = datetime.fromisoformat(
                        secret.next_rotation_time.rstrip("Z")
                    ).replace(tzinfo=timezone.utc)
                    rotation_overdue = next_rotation < datetime.now(timezone.utc)
                except (ValueError, AttributeError):
                    pass

            if rotation_days is not None and rotation_days <= MAX_ROTATION_DAYS and not rotation_overdue:
                report.status = "PASS"
                report.status_extended = (
                    f"Secret {secret.name} has automatic rotation enabled "
                    f"with a period of {rotation_days} days."
                )
            elif rotation_overdue:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} has rotation configured ({rotation_days} days) "
                    f"but the scheduled rotation is overdue (next_rotation_time has passed)."
                )
            elif rotation_days is not None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} has rotation enabled but the period "
                    f"({rotation_days} days) exceeds the {MAX_ROTATION_DAYS}-day maximum."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} does not have automatic rotation enabled."
                )

            findings.append(report)
        return findings
