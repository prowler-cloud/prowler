from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.vertexai.vertexai_client import vertexai_client


class vertexai_workbench_instance_auto_upgrade_enabled(Check):
    """Ensure Vertex AI Workbench instances have automatic upgrades scheduled.

    Workbench only upgrades an instance automatically when the
    `notebook-upgrade-schedule` metadata key holds a Unix-cron schedule.
    The check does not evaluate how often the schedule runs.
    - PASS: The instance has a non-empty `notebook-upgrade-schedule`.
    - FAIL: The instance is never upgraded automatically.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the automatic upgrade check across all Workbench instances.

        Returns:
            A list of `Check_Report_GCP` findings, one per non-deleted
            Workbench instance.
        """
        findings = []
        for instance in vertexai_client.workbench_instances:
            if instance.state == "DELETED":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.upgrade_schedule:
                report.status = "PASS"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has automatic upgrades scheduled ({instance.upgrade_schedule})."
            else:
                report.status = "FAIL"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} does not have automatic upgrades scheduled."
            findings.append(report)
        return findings
