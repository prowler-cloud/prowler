from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.config.config_client import config_client


class config_recorder_all_regions_enabled(Check):
    def execute(self):
        findings = []
        for recorder in config_client.recorders:
            report = Check_Report_AWS(self.metadata())
            report.region = recorder.region
            report.resource_arn = config_client.__get_recorder_arn_template__(
                recorder.region
            )
            report.resource_id = (
                config_client.audited_account if not recorder.name else recorder.name
            )
            # Check if Config is enabled in region
            if not recorder.name:
                report.status = "FAIL"
                report.status_extended = "No AWS Config recorders in region."
            else:
                if recorder.recording:
                    if recorder.last_status == "Failure":
                        report.status = "FAIL"
                        report.status_extended = (
                            f"AWS Config recorder {recorder.name} in failure state."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"AWS Config recorder {recorder.name} is enabled."
                        )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"AWS Config recorder {recorder.name} is disabled."
                    )
            if report.status == "FAIL" and (
                config_client.audit_config.get("mute_non_default_regions", False)
                and not recorder.region == config_client.region
            ):
                report.muted = True

            findings.append(report)

        return findings
