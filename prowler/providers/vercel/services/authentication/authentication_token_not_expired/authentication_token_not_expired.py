from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.authentication.authentication_client import (
    authentication_client,
)


class authentication_token_not_expired(Check):
    """Check if API tokens have not expired.

    This class verifies whether each Vercel API token is still valid by
    checking its expiration date against the current time.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Token Expiration check.

        Iterates over all tokens and checks if each token has expired.
        Tokens without an expiration date are considered valid (no expiry set).

        Returns:
            List[CheckReportVercel]: A list of reports for each token.
        """
        findings = []
        now = datetime.now(timezone.utc)
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
            elif token.expires_at > now:
                report.status = "PASS"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) is valid and expires "
                    f"on {token.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) has expired "
                    f"on {token.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                )

            findings.append(report)

        return findings
