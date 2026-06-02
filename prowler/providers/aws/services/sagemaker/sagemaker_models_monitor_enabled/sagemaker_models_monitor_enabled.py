from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_models_monitor_enabled(Check):
    def execute(self):
        findings = []
        for monitoring_schedule in sagemaker_client.sagemaker_monitoring_schedules:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=monitoring_schedule
            )
            if monitoring_schedule.schedule_status == "NOT_AVAILABLE":
                report.status = "FAIL"
                report.status_extended = f"No SageMaker monitoring schedules found in region {monitoring_schedule.region}."
            elif monitoring_schedule.schedule_status == "Scheduled":
                report.status = "PASS"
                report.status_extended = f"SageMaker monitoring schedule {monitoring_schedule.name} is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker monitoring schedule {monitoring_schedule.name} is not active ({monitoring_schedule.schedule_status})."
            findings.append(report)
        return findings
