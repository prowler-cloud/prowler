from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)

PQC_APIGATEWAY_POLICIES_DEFAULT = [
    "SecurityPolicy_TLS13_1_3_2025_09",
]


class apigateway_domain_name_pqc_tls_enabled(Check):
    """Verify that every API Gateway custom domain name uses a post-quantum TLS policy.

    A custom domain name PASSES when its ``securityPolicy`` belongs to the
    configured allowlist of enhanced post-quantum policies.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        pqc_policies = apigateway_client.audit_config.get(
            "apigateway_pqc_tls_allowed_policies", PQC_APIGATEWAY_POLICIES_DEFAULT
        )
        for domain in apigateway_client.domain_names:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            policy = domain.security_policy or "<none>"
            if domain.security_policy in pqc_policies:
                report.status = "PASS"
                report.status_extended = (
                    f"API Gateway custom domain {domain.name} uses post-quantum "
                    f"TLS policy {policy}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"API Gateway custom domain {domain.name} uses TLS policy "
                    f"{policy}, which is not in the post-quantum allowlist."
                )
            findings.append(report)

        return findings
