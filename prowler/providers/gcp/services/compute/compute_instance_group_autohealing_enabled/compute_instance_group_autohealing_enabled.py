from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_group_autohealing_enabled(Check):
    """
    Ensure Managed Instance Groups have autohealing enabled with a valid health check.

    This check verifies whether GCP Managed Instance Groups (MIGs) have autohealing
    policies configured with valid health check references. Autohealing automatically
    recreates unhealthy instances based on application-level health checks.

    - PASS: The MIG has autohealing enabled with a valid health check configured.
    - FAIL: The MIG has no autohealing policies or is missing a health check reference.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        for instance_group in compute_client.instance_groups:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance_group,
                location=instance_group.region,
            )

            if not instance_group.auto_healing_policies:
                report.status = "FAIL"
                report.status_extended = f"Managed Instance Group {instance_group.name} does not have autohealing enabled."
            else:
                has_valid_health_check = any(
                    policy.health_check
                    for policy in instance_group.auto_healing_policies
                )

                if has_valid_health_check:
                    health_checks = [
                        policy.health_check
                        for policy in instance_group.auto_healing_policies
                        if policy.health_check
                    ]
                    report.status = "PASS"
                    report.status_extended = f"Managed Instance Group {instance_group.name} has autohealing enabled with health check(s): {', '.join(health_checks)}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Managed Instance Group {instance_group.name} has autohealing configured but is missing a valid health check reference."

            findings.append(report)

        return findings
