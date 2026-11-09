from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_insecure_ssl_ciphers(Check):
    def execute(self):
        """Evaluate HTTPS listener policies against the secure-policy allowlist.

        Returns:
            Reports describing each load balancer's TLS policy security status.
        """
        findings = []
        secure_ssl_policies = [
            "ELBSecurityPolicy-TLS-1-2-2017-01",
            "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
            "ELBSecurityPolicy-FS-1-2-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2020-10",
            "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "ELBSecurityPolicy-TLS13-1-3-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
            # Non-PQ FIPS TLS policies (TLS 1.2+ minimum). The TLS13-1-1 and
            # TLS13-1-0 FIPS variants stay out because they still allow TLS 1.1/1.0.
            "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04",
            "ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
            "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
            "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-2023-04",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-2023-04",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-2023-04",
            # Non-PQ FIPS RFC 9151 (CNSA 1.0) TLS policies (TLS 1.2+ minimum)
            "ELBSecurityPolicy-TLS13-1-3-RFC9151-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-RFC9151-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-Ext0-RFC9151-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP1-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP2-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP3-FIPS-2023-07",
            "ELBSecurityPolicy-TLS13-1-2-RFC9151-INTEROP4-FIPS-2023-07",
            # AWS post-quantum (PQ) TLS policies (TLS 1.2+ minimum)
            "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
            # AWS FIPS post-quantum (PQ) TLS policies (TLS 1.2+ minimum)
            "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
            "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
        ]
        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "PASS"
            report.status_extended = (
                f"ELBv2 {lb.name} does not have insecure SSL protocols or ciphers."
            )
            for listener in lb.listeners.values():
                if (
                    listener.protocol == "HTTPS"
                    and listener.ssl_policy not in secure_ssl_policies
                ):
                    report.status = "FAIL"
                    report.status_extended = f"ELBv2 {lb.name} has listeners with insecure SSL protocols or ciphers ({listener.ssl_policy})."

            findings.append(report)

        return findings
