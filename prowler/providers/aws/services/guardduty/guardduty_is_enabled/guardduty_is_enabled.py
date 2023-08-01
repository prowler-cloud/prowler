from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client
from prowler.providers.aws import aws_provider


class guardduty_is_enabled(Check):
    def execute(self):
        findings = []
        for detector in guardduty_client.detectors:
            report = Check_Report_AWS(self.metadata())
            report.region = detector.region
            report.resource_id = detector.id
            report.resource_arn = detector.arn
            report.resource_tags = detector.tags
            report.status = "PASS"
            report.status_extended = f"GuardDuty detector {detector.id} enabled"
            if not detector.id:
                report.status = "FAIL"
                report.status_extended = "GuardDuty is not enabled"
            elif detector.status is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} not configured"
                )
            elif not detector.status:
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} configured but suspended"
                )

            findings.append(report)

        for region in aws_provider.get_aws_available_regions():
            has_detector = False
            for finding in findings:
                if finding.region == region:
                    has_detector = True
                    break

            if not has_detector:
                report = Check_Report_AWS(self.metadata())
                report.region = region
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty in region {region} has no detectors"
                )
                findings.append(report)

        return findings
