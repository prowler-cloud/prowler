"""Check that ELBv2 HTTPS/TLS listeners use post-quantum TLS policies."""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client

PQ_TLS_POLICIES_DEFAULT = [
    "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
]


class elbv2_listener_pqc_tls_enabled(Check):
    """Verify that every ELBv2 HTTPS or TLS listener uses a post-quantum TLS policy.

    This check evaluates whether each HTTPS (ALB) or TLS (NLB) listener on an
    ELBv2 load balancer terminates TLS with a security policy that offers
    post-quantum (PQ) hybrid key exchange (ML-KEM 768 combined with ECDHE).
    - PASS: All HTTPS/TLS listeners on the load balancer use a PQ TLS policy.
    - FAIL: At least one HTTPS/TLS listener uses a non-PQ TLS policy.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the PQ TLS policy check for every ELBv2 load balancer.

        Returns:
            A list of reports, one per load balancer that has HTTPS/TLS listeners.
        """
        findings = []
        pq_tls_policies = elbv2_client.audit_config.get(
            "elbv2_listener_pqc_tls_allowed_policies", PQ_TLS_POLICIES_DEFAULT
        )
        for lb in elbv2_client.loadbalancersv2.values():
            has_tls_listeners = False
            non_pq_policies = []
            for listener in lb.listeners.values():
                if listener.protocol in ("HTTPS", "TLS"):
                    has_tls_listeners = True
                    if listener.ssl_policy not in pq_tls_policies:
                        non_pq_policies.append(listener.ssl_policy)

            if not has_tls_listeners:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            if non_pq_policies:
                report.status = "FAIL"
                report.status_extended = f"ELBv2 {lb.name} has HTTPS/TLS listeners without post-quantum TLS policy ({', '.join(non_pq_policies)})."
            else:
                report.status = "PASS"
                report.status_extended = f"ELBv2 {lb.name} has all HTTPS/TLS listeners using a post-quantum TLS policy."

            findings.append(report)

        return findings
