import datetime

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.secretmanager.secretmanager_client import (
    secretmanager_client,
)


class secretmanager_secret_rotation_enabled(Check):
    """
    Ensure Secret Manager secrets have automatic rotation configured within the max rotation period.

    - PASS: Secret has a rotation period within the maximum (default 90 days) and the next rotation is not overdue.
    - FAIL: Secret has no rotation, the period exceeds the maximum, or the next rotation has been missed.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Evaluate every Secret Manager secret's rotation configuration against the maximum rotation period."""
        findings = []

        max_rotation_days = int(
            getattr(secretmanager_client, "audit_config", {}).get(
                "secretmanager_max_rotation_days", 90
            )
        )

        for secret in secretmanager_client.secrets:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=secret,
                resource_id=secret.name,
            )

            rotation_seconds = None
            if secret.rotation_period:
                try:
                    rotation_seconds = float(secret.rotation_period[:-1])
                except (ValueError, IndexError):
                    rotation_seconds = None

            rotation_overdue = False
            if rotation_seconds is not None and secret.next_rotation_time:
                try:
                    parsed = secret.next_rotation_time.replace("Z", "+00:00")
                    next_rotation_time = datetime.datetime.fromisoformat(parsed)
                    rotation_overdue = next_rotation_time < datetime.datetime.now(
                        datetime.timezone.utc
                    )
                except (ValueError, AttributeError):
                    rotation_overdue = True

            max_rotation_seconds = max_rotation_days * 86400
            rotation_days = (
                int(rotation_seconds // 86400) if rotation_seconds is not None else None
            )

            if rotation_seconds is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} does not have automatic rotation enabled."
                )
            elif rotation_seconds > max_rotation_seconds:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} has rotation enabled but the period "
                    f"({rotation_days} days) exceeds the {max_rotation_days}-day maximum."
                )
            elif rotation_overdue:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} has rotation configured "
                    f"({rotation_days} days) but the scheduled rotation is overdue."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Secret {secret.name} has automatic rotation enabled "
                    f"with a period of {rotation_days} days."
                )

            findings.append(report)

        return findings
