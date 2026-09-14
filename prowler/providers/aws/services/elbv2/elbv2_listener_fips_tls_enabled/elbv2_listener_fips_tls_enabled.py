from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_listener_fips_tls_enabled(Check):
    """Ensure every ELBv2 HTTPS or TLS listener uses a FIPS TLS security policy."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            if lb.listener_discovery_failed:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            tls_listeners = {
                listener_arn: listener
                for listener_arn, listener in lb.listeners.items()
                if listener.protocol in ("HTTPS", "TLS")
            }
            non_fips_listeners = [
                f"{listener.protocol}:{listener.port} ({listener_arn}) uses {listener.ssl_policy or '<none>'}"
                for listener_arn, listener in tls_listeners.items()
                if "FIPS" not in (listener.ssl_policy or "").split("-")
            ]
            if not tls_listeners:
                report.status = "PASS"
                report.status_extended = f"ELBv2 {lb.name} has no HTTPS/TLS listeners."
            elif non_fips_listeners:
                report.status = "FAIL"
                report.status_extended = f"ELBv2 {lb.name} has HTTPS/TLS listeners without a FIPS TLS security policy: {', '.join(non_fips_listeners)}."
            else:
                report.status = "PASS"
                report.status_extended = f"ELBv2 {lb.name} has all HTTPS/TLS listeners using a FIPS TLS security policy."
            findings.append(report)
        return findings
