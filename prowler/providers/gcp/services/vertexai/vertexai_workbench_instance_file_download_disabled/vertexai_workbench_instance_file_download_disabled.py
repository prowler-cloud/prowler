from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.vertexai.vertexai_client import vertexai_client


class vertexai_workbench_instance_file_download_disabled(Check):
    """Ensure Vertex AI Workbench instances have file downloads disabled.

    JupyterLab lets users download any file from the instance through the
    browser unless the `notebook-disable-downloads` metadata key is `true`.
    - PASS: The instance has `notebook-disable-downloads` set to `true`.
    - FAIL: Notebook users can download files from the JupyterLab UI.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the file download check across all Workbench instances.

        Returns:
            A list of `Check_Report_GCP` findings, one per non-deleted
            Workbench instance.
        """
        findings = []
        for instance in vertexai_client.workbench_instances:
            if instance.state == "DELETED":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.file_download_disabled:
                report.status = "PASS"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has file downloads disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has file downloads enabled."
            findings.append(report)
        return findings
