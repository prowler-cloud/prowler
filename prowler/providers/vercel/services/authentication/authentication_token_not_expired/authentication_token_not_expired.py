from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel, Severity
from prowler.providers.vercel.services.authentication.authentication_client import (
    authentication_client,
)


class authentication_token_not_expired(Check):
    """Check if API tokens have not expired or are about to expire.

    This class verifies whether each Vercel API token is still valid by
    checking its expiration date against the current time. Tokens expiring
    within a configurable threshold (default: 7 days) are flagged as
    about to expire with medium severity.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Token Expiration check.

        Iterates over all tokens and checks if each token has expired or
        is about to expire soon. The threshold is configurable via
        ``days_to_expire_threshold`` in audit_config (default: 7 days).
        Tokens without an expiration date are considered valid (no expiry set).

        Returns:
            List[CheckReportVercel]: A list of reports for each token.
        """
        findings = []
        now = datetime.now(timezone.utc)
        days_to_expire_threshold = authentication_client.audit_config.get(
            "days_to_expire_threshold", 7
        )
        for token in authentication_client.tokens.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=token,
                resource_name=token.name,
                resource_id=token.id,
            )

            if token.expires_at is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) does not have an expiration "
                    f"date set and is currently valid."
                )
            elif token.expires_at <= now:
                report.status = "FAIL"
                report.check_metadata.Severity = Severity.high
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) has expired "
                    f"on {token.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                )
            else:
                days_left = (token.expires_at - now).days
                if days_left <= days_to_expire_threshold:
                    report.status = "FAIL"
                    report.check_metadata.Severity = Severity.medium
                    report.status_extended = (
                        f"Token '{token.name}' ({token.id}) is about to expire "
                        f"in {days_left} days "
                        f"on {token.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Token '{token.name}' ({token.id}) is valid and expires "
                        f"on {token.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                    )

            findings.append(report)

        return findings
