from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.iam.iam_client import iam_client

# Days threshold above which a Bedrock long-term API key is considered effectively non-expiring.
NEVER_EXPIRES_THRESHOLD_DAYS = 10000


class bedrock_api_key_no_long_term_credentials(Check):
    """Amazon Bedrock long-term API keys should not be used outside of exploration.

    AWS recommends short-term Bedrock API keys (session-scoped, valid up to 12 hours)
    for any non-exploratory workload. ``ListServiceSpecificCredentials`` only enumerates
    long-term keys, so every key inspected here is by definition a long-term credential.

    PASS when the long-term key has already expired (it can no longer authenticate).
    FAIL (critical) when the key is configured to never expire.
    FAIL (high) for any other active long-term key.
    """

    def execute(self):
        findings = []
        for api_key in iam_client.service_specific_credentials:
            if api_key.service_name != "bedrock.amazonaws.com":
                continue
            if not api_key.expiration_date:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=api_key)
            now = datetime.now(timezone.utc)

            if api_key.expiration_date <= now:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock long-term API key {api_key.id} in user "
                    f"{api_key.user.name} has already expired and can no longer "
                    f"authenticate."
                )
            elif (api_key.expiration_date - now).days > NEVER_EXPIRES_THRESHOLD_DAYS:
                report.status = "FAIL"
                report.check_metadata.Severity = Severity.critical
                report.status_extended = (
                    f"Bedrock long-term API key {api_key.id} in user "
                    f"{api_key.user.name} is configured to never expire. Use "
                    f"short-term Bedrock API keys (session-scoped, valid up to "
                    f"12 hours) for non-exploratory workloads instead."
                )
            else:
                days_until_expiration = (api_key.expiration_date - now).days
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock long-term API key {api_key.id} in user "
                    f"{api_key.user.name} is active and will expire in "
                    f"{days_until_expiration} days. Use short-term Bedrock API "
                    f"keys (session-scoped, valid up to 12 hours) for "
                    f"non-exploratory workloads instead."
                )

            findings.append(report)

        return findings
