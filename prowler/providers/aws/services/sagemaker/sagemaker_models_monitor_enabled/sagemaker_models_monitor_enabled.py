from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_models_monitor_enabled(Check):
    def execute(self):
        findings = []
        monitoring_schedule_exists = True
        monitoring_schedule_is_scheduled = False
        for monitoring_schedule in sagemaker_client.sagemaker_monitoring_schedules:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=monitoring_schedule
            )
            if monitoring_schedule.schedule_status == "Scheduled":
                monitoring_schedule_is_scheduled = True
                break

            else:
                if monitoring_schedule.schedule_status == "NOT_AVAILABLE":
                    monitoring_schedule_exists = False

        if not monitoring_schedule_exists:
            report.status = "FAIL"
            report.status_extended = f"SageMaker monitoring schedules in account {sagemaker_client.audited_account} do not exist."
            findings.append(report)
        else:
            if monitoring_schedule_is_scheduled:
                report.status = "PASS"
                report.status_extended = f"SageMaker monitoring schedule {monitoring_schedule.name} is enabled."
                findings.append(report)
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker monitoring schedule {monitoring_schedule.name} is not active."
                findings.append(report)
        return findings
