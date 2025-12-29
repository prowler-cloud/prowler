from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.logging.logging_client import logging_client


class compute_configuration_changes(Check):
    """Detect Compute Engine configuration changes in Cloud Audit Logs.

    This check examines Cloud Audit Logs (Admin Activity) for recent Compute Engine
    configuration changes within a configurable lookback window. It surfaces
    configuration modifications such as instance settings, disks, and network changes
    so operators can review unexpected modifications.

    - PASS: No Compute Engine configuration changes detected in the lookback period.
    - FAIL: Compute Engine configuration changes were detected in the lookback period.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        for project_id in logging_client.project_ids:
            audit_entries = logging_client.compute_audit_entries.get(project_id, [])

            if not audit_entries:
                # No changes detected - PASS
                project_obj = logging_client.projects.get(project_id)
                report = Check_Report_GCP(
                    metadata=self.metadata(),
                    resource=project_obj,
                    project_id=project_id,
                    location=logging_client.region,
                    resource_name=(getattr(project_obj, "name", None) or project_id),
                    resource_id=project_id,
                )
                report.status = "PASS"
                report.status_extended = f"No Compute Engine configuration changes detected in project {project_id}."
                findings.append(report)
            else:
                # Changes detected - generate one FAIL finding per change
                for entry in audit_entries:
                    report = Check_Report_GCP(
                        metadata=self.metadata(),
                        resource=entry,
                        project_id=project_id,
                        location=logging_client.region,
                        resource_name=entry.resource_name,
                        resource_id=entry.insert_id,
                    )
                    report.status = "FAIL"

                    # Build detailed status message
                    actor = entry.principal_email or "unknown actor"
                    timestamp = entry.timestamp
                    method = entry.method_name

                    report.status_extended = (
                        f"Compute Engine configuration change detected: {method} "
                        f"on resource {entry.resource_name} by {actor} at {timestamp} "
                        f"in project {project_id}."
                    )
                    findings.append(report)

        return findings
