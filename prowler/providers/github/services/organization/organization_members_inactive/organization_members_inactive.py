from datetime import datetime, timedelta, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_members_inactive(Check):
    """Check if organization members have been inactive for extended periods.

    This class verifies whether organization members have recent activity within the last 30 days.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Members Inactive check.

        Iterates over all organizations and checks if members have been inactive for extended periods.

        Returns:
            List[CheckReportGithub]: A list of reports for each organization
        """
        findings = []

        # Max inactivity threshold is 30 days due to GitHub API limitation
        inactivity_threshold = timedelta(days=30)
        current_time = datetime.now(timezone.utc)

        for org in organization_client.organizations.values():
            if org.members is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)

                inactive_members = []

                for member in org.members:
                    is_inactive = False

                    if member.last_activity is None:
                        is_inactive = True
                    else:
                        time_since_activity = current_time - member.last_activity
                        if time_since_activity > inactivity_threshold:
                            is_inactive = True

                    if is_inactive:
                        inactive_members.append(member.login)

                if inactive_members:
                    report.status = "FAIL"
                    report.status_extended = f"Organization {org.name} has {len(inactive_members)} inactive members: {', '.join(inactive_members[:5])}{'...' if len(inactive_members) > 5 else ''}"
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Organization {org.name} has no inactive members detected"
                    )

                findings.append(report)

        return findings
