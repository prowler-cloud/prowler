from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_chat_report_policy_configured(Check):
    """Check if Defender report submission policy is properly configured for Teams security reporting.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Defender report submission policy settings.

        This method checks if Defender report submission policy is properly configured for Teams security reporting.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        report_submission_policy = defender_client.report_submission_policy

        if report_submission_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=report_submission_policy,
                resource_name="Defender Security Reporting Policy",
                resource_id="defenderSecurityReportingPolicy",
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

            if defender_settings_valid:
                report.status = "PASS"
                report.status_extended = "Defender report submission policy is properly configured for Teams security reporting."
            else:
                report.status = "FAIL"
                report.status_extended = "Defender report submission policy is not properly configured for Teams security reporting."

            findings.append(report)

        return findings
