from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpn.vpn_client import vpn_client

WEAK_ENCRYPTION = ["des", "3des"]


class vpn_weak_encryption(Check):
    """Check if VPN connections use weak encryption algorithms (DES, 3DES)."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for conn in vpn_client.vpn_connections:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=conn,
            )
            report.region = conn.region
            report.resource_id = conn.id
            report.resource_arn = f"huaweicloud:vpn:{conn.region}:{vpn_client.audited_account}:connection/{conn.id}"

            weak_algorithms = []

            if conn.ike_encryption_algorithm.lower() in WEAK_ENCRYPTION:
                weak_algorithms.append(f"IKE: {conn.ike_encryption_algorithm}")

            if conn.ipsec_encryption_algorithm.lower() in WEAK_ENCRYPTION:
                weak_algorithms.append(f"IPSec: {conn.ipsec_encryption_algorithm}")

            if weak_algorithms:
                report.status = "FAIL"
                report.status_extended = (
                    f"VPN connection '{conn.name}' ({conn.id}) uses weak encryption: "
                    f"{', '.join(weak_algorithms)}. Use AES-128 or AES-256 instead."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"VPN connection '{conn.name}' ({conn.id}) uses strong encryption "
                    f"(IKE: {conn.ike_encryption_algorithm}, IPSec: {conn.ipsec_encryption_algorithm})."
                )

            findings.append(report)

        return findings
