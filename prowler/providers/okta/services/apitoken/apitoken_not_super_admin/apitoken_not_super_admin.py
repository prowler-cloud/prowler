from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.api_token_client import api_token_client
from prowler.providers.okta.services.apitoken.lib.api_token_helpers import (
    missing_api_token_scope_finding,
    missing_user_roles_scope_for_token_finding,
    owner_has_super_admin,
)


class apitoken_not_super_admin(Check):
    """Ensure Okta API tokens are not owned by Super Admin users."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate every active API token owner's assigned admin roles."""
        org_domain = api_token_client.provider.identity.org_domain
        missing_api_token_scope = api_token_client.missing_scope.get("api_tokens")
        if missing_api_token_scope:
            return [
                missing_api_token_scope_finding(
                    self.metadata(),
                    org_domain,
                    missing_api_token_scope,
                    additional_required=["okta.roles.read", "okta.groups.read"],
                )
            ]

        missing_user_roles_scope = api_token_client.missing_scope.get("user_roles")
        # `okta.groups.read` is needed to resolve admin roles inherited via
        # group membership. Without it we fall back to direct-only role
        # assignments, which Okta returns for `/api/v1/users/{id}/roles` —
        # commonly empty for trial accounts where Super Admin is granted
        # through the default admin group. The finding stays evaluable but
        # is flagged as best-effort so operators know to grant the scope.
        missing_user_groups_scope = api_token_client.missing_scope.get("user_groups")
        findings: list[CheckReportOkta] = []
        for token in api_token_client.api_tokens.values():
            report = CheckReportOkta(
                metadata=self.metadata(), resource=token, org_domain=org_domain
            )
            if missing_user_roles_scope:
                report = missing_user_roles_scope_for_token_finding(
                    self.metadata(), org_domain, token, missing_user_roles_scope
                )
            elif owner_has_super_admin(token):
                report.status = "FAIL"
                report.status_extended = (
                    f"API token {token.name} is owned by user {token.user_id} "
                    "with the Super Admin role. Use a dedicated service account "
                    "with least-privilege admin roles instead."
                )
            else:
                roles = (
                    ", ".join(token.owner_roles)
                    if token.owner_roles
                    else "no admin roles returned"
                )
                caveat = (
                    " Group-inherited roles were not checked because the "
                    f"`{missing_user_groups_scope}` scope is missing — grant "
                    "it to detect Super Admin assigned via group membership."
                    if missing_user_groups_scope
                    else ""
                )
                report.status = "PASS"
                report.status_extended = (
                    f"API token {token.name} owner {token.user_id} is not "
                    f"assigned Super Admin ({roles}).{caveat}"
                )
            findings.append(report)
        return findings
