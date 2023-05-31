from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_block_project_wide_ssh_keys_disabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = compute_client.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "FAIL"
            report.status_extended = f"The VM Instance {instance.name} is making use of common/shared project-wide SSH key(s)."
            if instance.metadata.get("items"):
                for item in instance.metadata["items"]:
                    if (
                        item["key"] == "block-project-ssh-keys"
                        and item["value"] == "true"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"The VM Instance {instance.name} is not making use of common/shared project-wide SSH key(s)."
                        break
            findings.append(report)

        return findings
