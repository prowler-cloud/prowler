from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.apitoken.api_token_client import api_token_client
from prowler.providers.okta.services.apitoken.lib.api_token_helpers import (
    network_zone_restriction_status,
)


class apitoken_restricted_to_network_zone(Check):
    """Ensure Okta API tokens are restricted to known Network Zones."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate every active API token's network condition."""
        org_domain = api_token_client.provider.identity.org_domain
        findings: list[CheckReportOkta] = []
        for token in api_token_client.api_tokens.values():
            report = CheckReportOkta(
                metadata=self.metadata(), resource=token, org_domain=org_domain
            )
            report.status, report.status_extended = network_zone_restriction_status(
                token, api_token_client.known_network_zone_ids
            )
            findings.append(report)
        return findings
