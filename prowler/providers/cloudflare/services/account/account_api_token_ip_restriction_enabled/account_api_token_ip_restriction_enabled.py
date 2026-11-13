from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)
from prowler.providers.cloudflare.services.account.token_manual import (
    token_listing_manual_reports,
)

# Allow-list entries that permit every source address.
ANY_ADDRESS_CIDRS = {"0.0.0.0/0", "::/0"}


class account_api_token_ip_restriction_enabled(Check):
    """Ensure that active API tokens are restricted to an allow-list of source IPs.

    Only an allow-list limits where a token can be used from. A deny-list on its
    own, or an allow-list containing 0.0.0.0/0 or ::/0, still lets a leaked token
    be used from (almost) anywhere.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the client IP filtering of every active API token.

        Returns:
            PASS for tokens restricted to an allow-list without 0.0.0.0/0 or ::/0,
            FAIL otherwise, and MANUAL per account whose account-owned tokens
            could not be listed.
        """
        findings = token_listing_manual_reports(
            self, account_client, "client IP address filtering"
        )
        for token in account_client.tokens:
            if token.status != "active":
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=token,
                resource_name=token.unique_name,
            )
            label = f"API token {token.name} ({token.owner}-owned)"
            allow_list = [cidr.strip() for cidr in token.ip_allow_list]

            if not allow_list:
                report.status = "FAIL"
                report.status_extended = (
                    f"{label} only denies specific client IP addresses and can be used from any other address."
                    if token.ip_deny_list
                    else f"{label} does not have client IP address filtering configured."
                )
            elif ANY_ADDRESS_CIDRS & set(allow_list):
                report.status = "FAIL"
                report.status_extended = (
                    f"{label} allows client IP addresses from any address "
                    f"({', '.join(sorted(ANY_ADDRESS_CIDRS & set(allow_list)))})."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"{label} is restricted to an allow-list of client IP addresses."
                )
            findings.append(report)
        return findings
