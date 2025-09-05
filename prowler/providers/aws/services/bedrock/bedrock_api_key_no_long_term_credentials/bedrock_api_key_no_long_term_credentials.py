from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class bedrock_api_key_no_long_term_credentials(Check):
    """
    Bedrock API keys should be short-lived to reduce the risk of unauthorized access.
    This check verifies if there are any long-term Bedrock API keys.
    If there are, it checks if they are expired or will be expired.
    If they are expired, it will be marked as PASS.
    If they are not expired, it will be marked as FAIL and the severity will be critical if the key will never expire.
    """

    def execute(self):
        """
        Execute the Bedrock API key no long-term credentials check.

        Iterate over all the Bedrock API keys and check if they are expired or will be expired.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """

        findings = []
        for api_key in iam_client.service_specific_credentials:
            if api_key.service_name != "bedrock.amazonaws.com":
                continue
            if api_key.expiration_date:
                report = Check_Report_AWS(metadata=self.metadata(), resource=api_key)
                # Check if the expiration date is in the future
                if api_key.expiration_date > datetime.now(timezone.utc):
                    report.status = "FAIL"
                    # Get the days until the expiration date
                    days_until_expiration = (
                        api_key.expiration_date - datetime.now(timezone.utc)
                    ).days
                    if days_until_expiration > 10000:
                        self.Severity = "critical"
                        report.status_extended = f"Long-term Bedrock API key {api_key.id} in user {api_key.user.name} exists and never expires."
                    else:
                        report.status_extended = f"Long-term Bedrock API key {api_key.id} in user {api_key.user.name} exists and will expire in {days_until_expiration} days."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Long-term Bedrock API key {api_key.id} in user {api_key.user.name} exists but has expired."
                findings.append(report)

        return findings
