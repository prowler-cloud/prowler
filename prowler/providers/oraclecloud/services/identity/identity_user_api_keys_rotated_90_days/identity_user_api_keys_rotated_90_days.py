"""Check if user API keys rotate within 90 days or less."""

from datetime import datetime, timezone

import pytz

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)

maximum_expiration_days = 90


class identity_user_api_keys_rotated_90_days(Check):
    """Check if user API keys rotate within 90 days or less."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_api_keys_rotated_90_days check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for user in identity_client.users:
            # Check if user has API keys
            if user.api_keys:
                for api_key in user.api_keys:
                    # Only check active API keys
                    if api_key.lifecycle_state == "ACTIVE":
                        report = Check_Report_OCI(
                            metadata=self.metadata(),
                            resource=user,
                            region=user.region,
                            resource_name=user.name,
                            resource_id=user.id,
                            compartment_id=user.compartment_id,
                        )

                        # Calculate age of the API key
                        now = datetime.now(timezone.utc)
                        # Ensure api_key.time_created is timezone aware
                        if api_key.time_created.tzinfo is None:
                            key_created = api_key.time_created.replace(tzinfo=pytz.utc)
                        else:
                            key_created = api_key.time_created

                        age_days = (now - key_created).days

                        if age_days > maximum_expiration_days:
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has API key (fingerprint: {api_key.fingerprint[:16]}...) that has not been rotated in {age_days} days (over 90 days)."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"User {user.name} has API key (fingerprint: {api_key.fingerprint[:16]}...) that was created {age_days} days ago (within 90 days)."

                        findings.append(report)
            else:
                # User has no API keys
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=user,
                    region=user.region,
                    resource_name=user.name,
                    resource_id=user.id,
                    compartment_id=user.compartment_id,
                )
                report.status = "PASS"
                report.status_extended = f"User {user.name} does not have any API keys."
                findings.append(report)

        return findings
