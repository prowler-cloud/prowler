"""Check Ensure user customer secret keys rotate within 90 days or less."""

from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_user_customer_secret_keys_rotated_90_days(Check):
    """Check Ensure user customer secret keys rotate within 90 days or less."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_customer_secret_keys_rotated_90_days check."""
        findings = []

        # Calculate 90 days ago from now
        current_time = datetime.now(timezone.utc)
        max_age = current_time - timedelta(days=90)

        # Check each user's customer secret keys
        for user in identity_client.users:
            if not user.customer_secret_keys:
                continue

            for key in user.customer_secret_keys:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=key,
                    region=user.region,
                    resource_name=f"{user.name} - Customer Secret Key",
                    resource_id=key.id,
                    compartment_id=user.compartment_id,
                )

                # Check if key is older than 90 days
                key_age_days = (current_time - key.time_created).days

                if key.time_created < max_age:
                    report.status = "FAIL"
                    report.status_extended = f"User '{user.name}' has a customer secret key created {key_age_days} days ago (on {key.time_created.strftime('%Y-%m-%d')}), which exceeds the 90-day rotation period."
                else:
                    report.status = "PASS"
                    report.status_extended = f"User '{user.name}' has a customer secret key created {key_age_days} days ago, which is within the 90-day rotation period."

                findings.append(report)

        return findings
