from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_group_multiple_zones(Check):
    """
    Ensure Managed Instance Groups span multiple zones for high availability.

    This check verifies whether GCP Managed Instance Groups (MIGs) are distributed
    across multiple zones to ensure high availability and fault tolerance.

    - PASS: The MIG spans the minimum required zones (configurable via mig_min_zones).
    - FAIL: The MIG does not meet the minimum zone requirement.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        min_zones = compute_client.audit_config.get("mig_min_zones", 2)

        for instance_group in compute_client.instance_groups:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance_group,
                location=instance_group.region,
            )

            zone_count = len(instance_group.zones)
            zones_str = ", ".join(instance_group.zones)

            report.status = "PASS"
            if instance_group.is_regional:
                report.status_extended = f"Managed Instance Group {instance_group.name} is a regional MIG spanning {zone_count} zones ({zones_str})."
            else:
                report.status_extended = f"Managed Instance Group {instance_group.name} spans {zone_count} zones ({zones_str})."

            if zone_count < min_zones:
                report.status = "FAIL"
                if instance_group.is_regional:
                    report.status_extended = f"Managed Instance Group {instance_group.name} is a regional MIG but only spans {zone_count} zone(s) ({zones_str}), minimum required is {min_zones}."
                else:
                    report.status_extended = f"Managed Instance Group {instance_group.name} is a zonal MIG running only in {zones_str}, consider converting to a regional MIG for high availability."

            findings.append(report)

        return findings
