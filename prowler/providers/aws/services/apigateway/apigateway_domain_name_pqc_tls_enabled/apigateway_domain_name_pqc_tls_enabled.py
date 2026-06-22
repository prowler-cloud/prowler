from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)

PQC_APIGATEWAY_POLICIES_DEFAULT = [
    "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09",
    "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
    "SecurityPolicy_TLS13_1_2_PQ_2025_09",
]


def _get_allowed_policies(configured_policies: object) -> list[str]:
    if not isinstance(configured_policies, list):
        return PQC_APIGATEWAY_POLICIES_DEFAULT

    return configured_policies


class apigateway_domain_name_pqc_tls_enabled(Check):
    """Verify that every API Gateway custom domain name uses a post-quantum TLS policy.

    A custom domain name PASSES when its ``securityPolicy`` belongs to the
    configured allowlist of enhanced post-quantum policies.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the API Gateway custom domain post-quantum TLS check.

        Returns:
            A list of reports for API Gateway custom domain names and their
            post-quantum TLS policy compliance status.
        """
        findings = []
        pqc_policies = _get_allowed_policies(
            apigateway_client.audit_config.get("apigateway_pqc_tls_allowed_policies")
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
