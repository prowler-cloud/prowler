from datetime import datetime, timedelta, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.authentication.authentication_client import (
    authentication_client,
)

STALE_THRESHOLD_DAYS = 90


class authentication_no_stale_tokens(Check):
    """Check if API tokens have been used recently.

    This class verifies whether each Vercel API token has been active within
    the last 90 days. Stale tokens that remain unused pose a security risk
    as they may have been forgotten or belong to former team members.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Stale Token check.

        Iterates over all tokens and checks if each token has been active
        within the last 90 days.

        Returns:
            List[CheckReportVercel]: A list of reports for each token.
        """
        findings = []
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=STALE_THRESHOLD_DAYS)

        for token in authentication_client.tokens.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=token,
                resource_name=token.name,
                resource_id=token.id,
            )

            if token.active_at is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) has no recorded activity "
                    f"and is considered stale."
                )
            elif token.active_at < stale_cutoff:
                days_inactive = (now - token.active_at).days
                report.status = "FAIL"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) has not been used for "
                    f"{days_inactive} days (last active: "
                    f"{token.active_at.strftime('%Y-%m-%d %H:%M UTC')}). "
                    f"Threshold is {STALE_THRESHOLD_DAYS} days."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Token '{token.name}' ({token.id}) was last active on "
                    f"{token.active_at.strftime('%Y-%m-%d %H:%M UTC')} "
                    f"(within the last {STALE_THRESHOLD_DAYS} days)."
                )

            findings.append(report)

        return findings
