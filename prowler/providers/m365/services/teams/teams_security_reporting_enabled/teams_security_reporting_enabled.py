from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client
from prowler.providers.m365.services.teams.teams_client import teams_client


class teams_security_reporting_enabled(Check):
    """Check if users can report security concerns in Teams.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Teams security reporting settings.

        This method checks if security reporting is properly configured in Teams
        and Defender settings.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        global_messaging_policy = teams_client.global_messaging_policy
        report_submission_policy = defender_client.report_submission_policy

        if global_messaging_policy and report_submission_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={
                    "teams_messaging_policy": global_messaging_policy.dict(),
                    "defender_policy": report_submission_policy.dict(),
                },
                resource_name="Teams Security Reporting Settings",
                resource_id="teamsSecurityReporting",
            )

            teams_reporting_enabled = (
                global_messaging_policy.allow_security_end_user_reporting
            )

            defender_settings_valid = (
                report_submission_policy.report_junk_to_customized_address
                and report_submission_policy.report_not_junk_to_customized_address
                and report_submission_policy.report_phish_to_customized_address
                and report_submission_policy.report_junk_addresses
                and report_submission_policy.report_not_junk_addresses
                and report_submission_policy.report_phish_addresses
                and not report_submission_policy.report_chat_message_enabled
                and report_submission_policy.report_chat_message_to_customized_address_enabled
            )

            if teams_reporting_enabled and defender_settings_valid:
                report.status = "PASS"
                report.status_extended = "Security reporting is properly configured in Teams and Defender settings."
            else:
                report.status = "FAIL"
                report.status_extended = "Security reporting is not properly configured in Teams and Defender settings."

            findings.append(report)

        return findings
