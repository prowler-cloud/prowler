from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.api_token_client import api_token_client
from prowler.providers.okta.services.apitoken.lib.api_token_helpers import (
    owner_has_super_admin,
)


class apitoken_not_super_admin(Check):
    """Ensure Okta API tokens are not owned by Super Admin users."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate every active API token owner's assigned admin roles."""
        org_domain = api_token_client.provider.identity.org_domain
        findings: list[CheckReportOkta] = []
        for token in api_token_client.api_tokens.values():
            report = CheckReportOkta(
                metadata=self.metadata(), resource=token, org_domain=org_domain
            )
            if owner_has_super_admin(token):
                report.status = "FAIL"
                report.status_extended = (
                    f"API token '{token.name}' is owned by user '{token.user_id}' "
                    "with the Super Admin role. Use a dedicated service account "
                    "with least-privilege admin roles instead."
                )
            else:
                roles = (
                    ", ".join(token.owner_roles)
                    if token.owner_roles
                    else "no admin roles returned"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"API token '{token.name}' owner '{token.user_id}' is not "
                    f"assigned Super Admin ({roles})."
                )
            findings.append(report)
        return findings
