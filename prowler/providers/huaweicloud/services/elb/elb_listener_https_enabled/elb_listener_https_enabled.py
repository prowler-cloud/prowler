from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.elb.elb_client import elb_client


class elb_listener_https_enabled(Check):
    """Check if ELB HTTP/HTTPS listeners use HTTPS instead of plaintext HTTP."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for listener in elb_client.listeners:
            protocol = listener.protocol.upper()
            if protocol not in ("HTTP", "HTTPS", "TERMINATED_HTTPS"):
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=listener)
            report.region = listener.region
            report.resource_id = listener.id
            report.resource_name = listener.name or listener.id
            report.resource_arn = f"huaweicloud:elb:{listener.region}:{elb_client.audited_account}:listener/{listener.id}"

            if protocol in ("HTTPS", "TERMINATED_HTTPS"):
                report.status = "PASS"
                report.status_extended = (
                    f"ELB listener {listener.name or listener.id} ({listener.id}) "
                    f"uses HTTPS protocol ({protocol}) on port {listener.protocol_port}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB listener {listener.name or listener.id} ({listener.id}) "
                    f"uses insecure HTTP protocol on port {listener.protocol_port}."
                )

            findings.append(report)

        return findings
