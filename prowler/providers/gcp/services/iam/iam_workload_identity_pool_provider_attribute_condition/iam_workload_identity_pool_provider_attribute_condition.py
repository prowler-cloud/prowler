from urllib.parse import urlparse

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.iam.iam_client import iam_client

# OIDC issuers whose tokens are minted for many independent tenants (any GitHub
# repository, any GitLab project, any Google account, ...). A provider that
# trusts one of these without an ``attributeCondition`` accepts identities
# outside the operator's control, so omitting the condition genuinely expands
# trust. A dedicated, single-tenant issuer only vends tokens to the operator's
# own workloads, so an attribute condition there is defense-in-depth rather than
# a requirement (see Google's guidance for GitHub and other shared issuers).
MULTI_TENANT_OIDC_ISSUER_HOSTS = {
    "token.actions.githubusercontent.com",  # GitHub Actions (any repository)
    "gitlab.com",  # GitLab.com SaaS (any project)
    "accounts.google.com",  # any Google account
    "app.terraform.io",  # HCP Terraform (any organization)
}


def _is_multi_tenant_issuer(issuer_uri: str) -> bool:
    """Return True when the OIDC issuer is a known multi-tenant/shared issuer."""
    if not issuer_uri:
        return False
    # hostname lowercases and strips port/userinfo (gitlab.com:443, user@host);
    # fall back to the raw string for bare hosts without a scheme.
    host = urlparse(issuer_uri).hostname or issuer_uri.lower()
    return host in MULTI_TENANT_OIDC_ISSUER_HOSTS


class iam_workload_identity_pool_provider_attribute_condition(Check):
    """Ensure WIF providers trusting a multi-tenant issuer enforce an attribute condition.

    A workload identity pool provider that trusts a multi-tenant issuer (GitHub
    Actions, GitLab.com, ...) without an ``attributeCondition`` accepts every
    external identity that issuer can mint. An attacker controlling any tenant on
    that platform can then authenticate through the provider and exchange tokens
    for federated credentials, surviving credential rotation. Providers that
    enforce an attribute condition, that trust a dedicated single-tenant issuer,
    that are not OIDC-based, that are disabled/inactive, or whose parent pool is
    disabled are reported as PASS.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Evaluate the attribute condition of each Workload Identity provider.

        Returns:
            list[Check_Report_GCP]: One report per workload identity pool
            provider. FAIL for active providers that trust a multi-tenant issuer
            without an attribute condition; PASS for providers that enforce one,
            trust a dedicated issuer, are not OIDC-based, or are
            disabled/inactive.
        """
        findings = []
        for provider in iam_client.workload_identity_pool_providers:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=provider,
                resource_id=provider.name,
                resource_name=provider.display_name or provider.id,
                location="global",
            )
            if provider.pool_disabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} belongs "
                    f"to the disabled pool {provider.pool_id}, which cannot vend "
                    "credentials."
                )
            elif provider.disabled or provider.state != "ACTIVE":
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} is not active and cannot vend credentials."
                )
            elif provider.attribute_condition:
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} enforces an attribute condition."
                )
            elif _is_multi_tenant_issuer(provider.issuer_uri):
                report.status = "FAIL"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} trusts the multi-tenant issuer "
                    f"{provider.issuer_uri} without an attribute condition, so any "
                    "identity from that issuer can authenticate through this provider."
                )
            elif provider.provider_type != "oidc":
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} is not an OIDC provider trusting a "
                    "multi-tenant issuer; an attribute condition is recommended as "
                    "defense-in-depth but not required."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Workload Identity Federation provider {provider.id} in pool "
                    f"{provider.pool_id} trusts a dedicated issuer; an attribute "
                    "condition is recommended as defense-in-depth but not required."
                )
            findings.append(report)

        return findings
