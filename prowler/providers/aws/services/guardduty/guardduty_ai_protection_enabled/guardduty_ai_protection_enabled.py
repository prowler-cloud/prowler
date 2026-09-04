from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_ai_protection_enabled(Check):
    """Ensure GuardDuty AI Protection is enabled on every active detector.

    AI Protection analyzes AWS CloudTrail data events from Amazon Bedrock, Amazon
    Bedrock AgentCore and Amazon SageMaker AI, which makes it the detective control
    for AI workloads.

    The feature has three observable states rather than two:

    1. Reported as ENABLED: PASS.
    2. Reported as DISABLED: FAIL.
    3. Not reported at all: MANUAL. GuardDuty omits features that the Region or the
       GuardDuty version does not offer, and "could not tell" is not "not
       compliant". The same account can carry a feature in some Regions and omit it
       in others, so absence cannot be read as disablement.

    A suspended detector, or one whose GetDetector call failed, is MANUAL as well:
    the feature state is unknown either way, and guardduty_is_enabled owns the
    detector-level finding. Regions with no detector at all are left to
    guardduty_is_enabled entirely.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Assess AI Protection on every GuardDuty detector in the account.

        Returns:
            list[Check_Report_AWS]: one report per detector that exists. PASS when AI
                Protection is enabled, FAIL when GuardDuty reported the feature
                disabled, and MANUAL when either the detector state or the feature
                itself was not reported.
        """
        findings = []
        for detector in guardduty_client.detectors:
            if not detector.enabled_in_account:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=detector)

            if not detector.status:
                report.status = "MANUAL"
                report.status_extended = f"GuardDuty detector {detector.id} is not enabled or could not be read, so AI Protection coverage could not be determined."
            elif detector.ai_protection is None:
                report.status = "MANUAL"
                report.status_extended = f"GuardDuty detector {detector.id} does not report the AI Protection feature, so verify manually whether AI Protection is available in region {detector.region}."
            elif detector.ai_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} has AI Protection enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"GuardDuty detector {detector.id} does not have AI Protection enabled."

            findings.append(report)
        return findings
