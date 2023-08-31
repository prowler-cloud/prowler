from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_centrally_managed(Check):
    def execute(self):
        findings = []
        for detector in guardduty_client.detectors:
            if detector.id:
                report = Check_Report_AWS(self.metadata())
                report.region = detector.region
                report.resource_id = detector.id
                report.resource_arn = detector.arn
                report.resource_tags = detector.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} is not centrally managed."
                )
                if detector.administrator_account:
                    report.status = "PASS"
                    report.status_extended = f"GuardDuty detector {detector.id} is centrally managed by account {detector.administrator_account}."
                elif detector.member_accounts:
                    report.status = "PASS"
                    report.status_extended = f"GuardDuty detector {detector.id} is administrator account with {len(detector.member_accounts)} member accounts."

                findings.append(report)

        return findings
