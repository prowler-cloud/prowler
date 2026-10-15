from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.vertexai.vertexai_client import vertexai_client


class vertexai_workbench_instance_root_access_disabled(Check):
    """Ensure Vertex AI Workbench instances have root access disabled.

    Workbench grants the notebook user passwordless sudo unless the
    `notebook-disable-root` metadata key is set to `true`.
    - PASS: The instance has `notebook-disable-root` set to `true`.
    - FAIL: The notebook user can obtain root on the instance.
    - MANUAL: Workbench instances could not be listed for the project.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the root access check across all Workbench instances.

        Returns:
            A list of `Check_Report_GCP` findings, one per non-deleted
            Workbench instance plus one per project that could not be listed.
        """
        findings = []
        for project_id in sorted(vertexai_client.workbench_instances_lookup_failed):
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=vertexai_client.projects[project_id],
                resource_id=project_id,
                project_id=project_id,
                location=vertexai_client.region,
            )
            report.status = "MANUAL"
            report.status_extended = f"Cannot evaluate Vertex AI Workbench instances in project {project_id}: instances could not be listed. Verify that notebooks.instances.list is granted to the scanning identity."
            findings.append(report)

        for instance in vertexai_client.workbench_instances:
            if instance.state == "DELETED":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.root_access_disabled:
                report.status = "PASS"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has root access disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has root access enabled."
            findings.append(report)
        return findings
