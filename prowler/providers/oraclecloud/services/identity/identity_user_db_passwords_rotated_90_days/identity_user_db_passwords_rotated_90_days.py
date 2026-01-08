"""Check Ensure user IAM Database Passwords rotate within 90 days."""

from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_user_db_passwords_rotated_90_days(Check):
    """Check Ensure user IAM Database Passwords rotate within 90 days."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_db_passwords_rotated_90_days check."""
        findings = []

        # Calculate 90 days ago from now
        current_time = datetime.now(timezone.utc)
        max_age = current_time - timedelta(days=90)

        # Check each user's database passwords
        for user in identity_client.users:
            if not user.db_passwords:
                continue

            for password in user.db_passwords:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=password,
                    region=user.region,
                    resource_name=f"{user.name} - DB Password",
                    resource_id=password.id,
                    compartment_id=user.compartment_id,
                )

                # Check if password is older than 90 days
                password_age_days = (current_time - password.time_created).days

                if password.time_created < max_age:
                    report.status = "FAIL"
                    report.status_extended = f"User '{user.name}' has a database password created {password_age_days} days ago (on {password.time_created.strftime('%Y-%m-%d')}), which exceeds the 90-day rotation period."
                else:
                    report.status = "PASS"
                    report.status_extended = f"User '{user.name}' has a database password created {password_age_days} days ago, which is within the 90-day rotation period."

                findings.append(report)

        return findings
