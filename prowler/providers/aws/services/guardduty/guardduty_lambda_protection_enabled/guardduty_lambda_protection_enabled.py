from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_lambda_protection_enabled(Check):
    def execute(self):
        findings = []
        for detector in guardduty_client.detectors:
            if detector.status:
                report = Check_Report_AWS(self.metadata())
                report.region = detector.region
                report.resource_id = detector.id
                report.resource_arn = detector.arn
                report.resource_tags = detector.tags
                report.status = "FAIL"
                report.status_extended = f"GuardDuty detector {detector.id} does not have Lambda Protection enabled."
                if detector.lambda_protection:
                    report.status = "PASS"
                    report.status_extended = f"GuardDuty detector {detector.id} has Lambda Protection enabled."
                findings.append(report)
        return findings
