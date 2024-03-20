from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


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
            report.status_extended = f"GuardDuty detector {detector.id} enabled."

            if not detector.enabled_in_account:
                report.status = "FAIL"
                report.status_extended = "GuardDuty is not enabled."
            elif detector.status is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} not configured."
                )
            elif not detector.status:
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty detector {detector.id} configured but suspended."
                )

            if report.status == "FAIL" and (
                guardduty_client.audit_config.get("mute_non_default_regions", False)
                and not detector.region == guardduty_client.region
            ):
                report.muted = True

            findings.append(report)

        return findings
