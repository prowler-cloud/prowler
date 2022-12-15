from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_no_high_severity_findings(Check):
    def execute(self):
        findings = []
        for detector in guardduty_client.detectors:
            report = Check_Report_AWS(self.metadata())
            report.region = detector.region
            report.resource_id = detector.id
            report.resource_arn = detector.arn
            report.status = "PASS"
            report.status_extended = f"GuardDuty detector {detector.id} does not have high severity findings."
            if len(detector.findings) > 0:
                report.status = "FAIL"
                report.status_extended = f"GuardDuty detector {detector.id} has {str(len(detector.findings))} high severity findings"

            findings.append(report)

        return findings
