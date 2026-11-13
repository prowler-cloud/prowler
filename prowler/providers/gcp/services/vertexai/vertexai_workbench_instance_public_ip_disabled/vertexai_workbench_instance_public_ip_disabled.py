from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.vertexai.vertexai_client import vertexai_client


class vertexai_workbench_instance_public_ip_disabled(Check):
    """Ensure Vertex AI Workbench instances do not have a public IP address.

    A Workbench instance with an external IP is directly reachable from, and can
    reach, the internet without passing through VPC egress controls.
    - PASS: The instance was created with `disablePublicIp` set.
    - FAIL: The instance has a public IP address assigned.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the public IP check across all Workbench instances.

        Returns:
            A list of `Check_Report_GCP` findings, one per non-deleted
            Workbench instance.
        """
        findings = []
        for instance in vertexai_client.workbench_instances:
            if instance.state == "DELETED":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            if instance.public_ip_disabled:
                report.status = "PASS"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} does not have a public IP address."
            else:
                report.status = "FAIL"
                report.status_extended = f"Vertex AI Workbench instance {instance.name} has a public IP address assigned, allowing direct internet access."
            findings.append(report)
        return findings
