from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.nat.nat_client import nat_client

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    1433: "MSSQL",
}


class nat_dnat_sensitive_ports(Check):
    """Check if NAT Gateway DNAT rules expose sensitive ports to the internet."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for rule in nat_client.dnat_rules:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=rule)
            report.region = rule.region
            report.resource_id = rule.id
            report.resource_arn = f"huaweicloud:nat:{rule.region}:{nat_client.audited_account}:dnat_rule/{rule.id}"

            if rule.external_service_port in SENSITIVE_PORTS:
                svc = SENSITIVE_PORTS[rule.external_service_port]
                report.status = "FAIL"
                report.status_extended = (
                    f"DNAT rule {rule.id} exposes sensitive port "
                    f"{rule.external_service_port} ({svc}) on "
                    f"{rule.floating_ip_address} to the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"DNAT rule {rule.id} exposes port "
                    f"{rule.external_service_port} on "
                    f"{rule.floating_ip_address} which is not a sensitive port."
                )

            findings.append(report)

        return findings
