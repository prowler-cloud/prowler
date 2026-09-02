from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.eip.eip_client import eip_client


class eip_unassociated(Check):
    """Check if there are unassociated EIPs (Elastic IPs not bound to any resource)."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for eip in eip_client.public_ips:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=eip,
            )
            report.region = eip.region
            report.resource_id = eip.id
            report.resource_arn = f"huaweicloud:eip:{eip.region}:{eip_client.audited_account}:publicip/{eip.id}"

            if eip.port_id:
                report.status = "PASS"
                report.status_extended = f"EIP {eip.public_ip_address} ({eip.id}) is associated with port {eip.port_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"EIP {eip.public_ip_address} ({eip.id}) is not associated with any resource."

            findings.append(report)

        return findings
