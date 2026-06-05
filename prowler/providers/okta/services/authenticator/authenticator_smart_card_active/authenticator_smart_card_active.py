from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.authenticator_helpers import (
    find_authenticator_by_key,
    missing_authenticator_resource,
    missing_authenticators_scope_finding,
)


class authenticator_smart_card_active(Check):
    """Ensure the Smart Card IdP authenticator is active."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate the Smart Card IdP authenticator status."""
        org_domain = authenticator_client.provider.identity.org_domain
        missing_scope = authenticator_client.missing_scope.get("authenticators")
        if missing_scope:
            return [
                missing_authenticators_scope_finding(
                    self.metadata(),
                    org_domain,
                    "smart_card_idp",
                    "Smart Card IdP authenticator",
                    missing_scope,
                )
            ]

        authenticator = find_authenticator_by_key(
            authenticator_client.authenticators, "smart_card_idp"
        )
        resource = authenticator or missing_authenticator_resource(
            "smart_card_idp", "Smart Card IdP authenticator"
        )
        report = CheckReportOkta(
            metadata=self.metadata(), resource=resource, org_domain=org_domain
        )
        if authenticator and authenticator.status.upper() == "ACTIVE":
            report.status = "PASS"
            report.status_extended = "Smart Card IdP authenticator is ACTIVE."
        elif authenticator:
            report.status = "FAIL"
            report.status_extended = (
                f"Smart Card IdP authenticator is not active; current status is "
                f"{authenticator.status}."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Smart Card IdP authenticator is not active or missing."
            )
        return [report]
