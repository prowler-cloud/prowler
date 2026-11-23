from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.elb.elb_client import elb_client


class elb_listener_secure_tls_policy(Check):
    """Check if ELB HTTPS listeners enforce TLS 1.2 or higher security policies."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for listener in elb_client.listeners:
            protocol = listener.protocol.upper()
            if protocol not in ("HTTPS", "TERMINATED_HTTPS"):
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=listener)
            report.region = listener.region
            report.resource_id = listener.id
            report.resource_name = listener.name or listener.id
            report.resource_arn = f"huaweicloud:elb:{listener.region}:{elb_client.audited_account}:listener/{listener.id}"

            if listener.security_policy_id:
                if listener.security_policy_protocols is None:
                    continue
                insecure_protocols = {
                    p
                    for p in listener.security_policy_protocols
                    if p.upper() in ("TLSV1", "TLSV1.1")
                }
                if insecure_protocols:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ELB listener {listener.name or listener.id} ({listener.id}) "
                        f"uses custom security policy {listener.security_policy_id} "
                        f"with insecure TLS protocols ({', '.join(sorted(insecure_protocols))})."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"ELB listener {listener.name or listener.id} ({listener.id}) "
                        f"uses custom security policy {listener.security_policy_id} "
                        f"with TLS 1.2 or higher."
                    )
            else:
                policy = listener.tls_ciphers_policy.lower()
                is_insecure = not policy or policy.startswith(
                    ("tls-1-0", "tls-1-1", "hybrid-policy-1-0")
                )
                if is_insecure:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ELB listener {listener.name or listener.id} ({listener.id}) "
                        f"uses insecure TLS policy ({listener.tls_ciphers_policy or 'unset'})."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"ELB listener {listener.name or listener.id} ({listener.id}) "
                        f"uses secure TLS policy ({listener.tls_ciphers_policy})."
                    )

            findings.append(report)

        return findings
