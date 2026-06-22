from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_models_monitor_enabled(Check):
    def execute(self):
        findings = []
        for monitoring_schedule in sagemaker_client.sagemaker_monitoring_schedules:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=monitoring_schedule
            )
            if monitoring_schedule.is_scheduled:
                report.status = "PASS"
                report.status_extended = f"SageMaker monitoring schedule {monitoring_schedule.name} is enabled in region {monitoring_schedule.region}."
            elif not monitoring_schedule.has_schedules:
                report.status = "FAIL"
                report.status_extended = f"No SageMaker monitoring schedules found in region {monitoring_schedule.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"No active SageMaker monitoring schedule in region {monitoring_schedule.region}; existing schedules are not in Scheduled status."
            findings.append(report)
        return findings
