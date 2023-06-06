from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_serial_ports_in_use(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(self.metadata())
            report.project_id = instance.project_id
            report.resource_id = instance.id
            report.resource_name = instance.name
            report.location = instance.zone
            report.status = "PASS"
            report.status_extended = f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ off"
            if instance.metadata.get("items"):
                for item in instance.metadata["items"]:
                    if item["key"] == "serial-port-enable" and item["value"] in [
                        "1",
                        "true",
                    ]:
                        report.status = "FAIL"
                        report.status_extended = f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ set to on"
                        break
            findings.append(report)

        return findings
