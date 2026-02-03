from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_group_load_balancer_attached(Check):
    """
    Ensure Managed Instance Groups are attached to load balancers.

    This check verifies whether GCP Managed Instance Groups (MIGs) are configured
    as backends for load balancers through backend services. MIGs without load
    balancer attachments cannot distribute traffic evenly across instances.

    - PASS: The MIG is attached to a load balancer via a backend service.
    - FAIL: The MIG is not attached to any load balancer.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        for instance_group in compute_client.instance_groups:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance_group,
                location=instance_group.region,
            )

            if instance_group.load_balanced:
                report.status = "PASS"
                report.status_extended = f"Managed Instance Group {instance_group.name} is attached to a load balancer."
            else:
                report.status = "FAIL"
                report.status_extended = f"Managed Instance Group {instance_group.name} is not attached to any load balancer."

            findings.append(report)

        return findings
