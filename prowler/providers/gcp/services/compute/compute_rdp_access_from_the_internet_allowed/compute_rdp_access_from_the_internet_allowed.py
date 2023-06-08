from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_rdp_access_from_the_internet_allowed(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for firewall in compute_client.firewalls:
            report = Check_Report_GCP(self.metadata())
            report.project_id = firewall.project_id
            report.resource_id = firewall.id
            report.resource_name = firewall.name
            report.status = "PASS"
            report.status_extended = f"Firewall {firewall.name} does not expose port 3389 (RDP) to the internet."
            opened_port = False
            for rule in firewall.allowed_rules:
                if rule["IPProtocol"] == "all":
                    opened_port = True
                    break
                elif rule["IPProtocol"] == "tcp":
                    if rule.get("ports") is None:
                        opened_port = True
                        break
                    else:
                        for port in rule["ports"]:
                            if port.find("-") != -1:
                                lower, higher = port.split("-")
                                if int(lower) <= 3389 and int(higher) >= 3389:
                                    opened_port = True
                                    break
                            elif int(port) == 3389:
                                opened_port = True
                            break
            if (
                "0.0.0.0/0" in firewall.source_ranges
                and firewall.direction == "INGRESS"
                and opened_port
            ):
                report.status = "FAIL"
                report.status_extended = f"Firewall {firewall.name} does exposes port 3389 (RDP) to the internet."
            findings.append(report)

        return findings
