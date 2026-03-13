"""Check Ensure user auth tokens rotate within 90 days or less."""

from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_user_auth_tokens_rotated_90_days(Check):
    """Check Ensure user auth tokens rotate within 90 days or less."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_auth_tokens_rotated_90_days check.

        Ensure user auth tokens rotate within 90 days or less.
        """
        findings = []

        # Calculate 90 days ago from now
        current_time = datetime.now(timezone.utc)
        max_age = current_time - timedelta(days=90)

        # Check each user's auth tokens
        for user in identity_client.users:
            if not user.auth_tokens:
                continue

            for token in user.auth_tokens:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=token,
                    region=user.region,
                    resource_name=f"{user.name} - Auth Token",
                    resource_id=token.id,
                    compartment_id=user.compartment_id,
                )

                # Check if token is older than 90 days
                token_age_days = (current_time - token.time_created).days

                if token.time_created < max_age:
                    report.status = "FAIL"
                    report.status_extended = f"User '{user.name}' has an auth token created {token_age_days} days ago (on {token.time_created.strftime('%Y-%m-%d')}), which exceeds the 90-day rotation period."
                else:
                    report.status = "PASS"
                    report.status_extended = f"User '{user.name}' has an auth token created {token_age_days} days ago, which is within the 90-day rotation period."

                findings.append(report)

        return findings
