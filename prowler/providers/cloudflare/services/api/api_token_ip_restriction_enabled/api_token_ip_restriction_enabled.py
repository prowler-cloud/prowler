from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.api.api_client import api_client


class api_token_ip_restriction_enabled(Check):
    """Ensure that Cloudflare API tokens have client IP address filtering configured.

    API tokens with IP address filtering restrict token usage to requests originating
    from specific IP addresses or CIDR ranges. Without IP filtering, a compromised
    token can be used from any network location.

    - PASS: The API token has at least one IP address restriction configured.
    - FAIL: The API token has no IP address filtering configured.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the API token IP restriction check.

        Iterates through all Cloudflare API tokens and verifies that each token
        has client IP address filtering configured via allow or deny lists.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if IP
            filtering is configured, or FAIL status if no IP restrictions exist.
        """
        findings = []
        for token in api_client.tokens:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=token,
            )

            has_ip_restriction = bool(token.ip_allow_list) or bool(
                token.ip_deny_list
            )

            if has_ip_restriction:
                report.status = "PASS"
                report.status_extended = (
                    f"API token {token.name} has client IP address filtering configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"API token {token.name} does not have client IP address filtering configured."
                )
            findings.append(report)
        return findings
