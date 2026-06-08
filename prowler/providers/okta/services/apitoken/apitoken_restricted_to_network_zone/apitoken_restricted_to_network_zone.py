from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.api_token_client import api_token_client
from prowler.providers.okta.services.apitoken.lib.api_token_helpers import (
    definite_network_zone_restriction_failure,
    missing_api_token_scope_finding,
    missing_network_zone_scope_for_token_finding,
    network_zone_restriction_status,
)


class apitoken_restricted_to_network_zone(Check):
    """Ensure Okta API tokens are restricted to known Network Zones."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate every active API token's network condition."""
        org_domain = api_token_client.provider.identity.org_domain
        missing_api_token_scope = api_token_client.missing_scope.get("api_tokens")
        if missing_api_token_scope:
            return [
                missing_api_token_scope_finding(
                    self.metadata(),
                    org_domain,
                    missing_api_token_scope,
                    additional_required=["okta.networkZones.read"],
                )
            ]

        missing_network_zone_scope = api_token_client.missing_scope.get("network_zones")
        findings: list[CheckReportOkta] = []
        for token in api_token_client.api_tokens.values():
            if missing_network_zone_scope:
                definite_failure = definite_network_zone_restriction_failure(token)
                if definite_failure:
                    report = CheckReportOkta(
                        metadata=self.metadata(),
                        resource=token,
                        org_domain=org_domain,
                    )
                    report.status, report.status_extended = definite_failure
                else:
                    report = missing_network_zone_scope_for_token_finding(
                        self.metadata(), org_domain, token, missing_network_zone_scope
                    )
            else:
                report = CheckReportOkta(
                    metadata=self.metadata(), resource=token, org_domain=org_domain
                )
                (
                    report.status,
                    report.status_extended,
                ) = network_zone_restriction_status(
                    token, api_token_client.known_network_zone_ids
                )
            findings.append(report)
        return findings
