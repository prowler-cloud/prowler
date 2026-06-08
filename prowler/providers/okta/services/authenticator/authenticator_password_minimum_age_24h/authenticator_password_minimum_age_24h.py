from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_minimum_age_24h(Check):
    """STIG V-273200 / OKTA-APP-000740.

    Every active Okta Password Policy must enforce a 24-hour minimum password age.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            field_name="min_age_minutes",
            requirement="minimum password age of at least 24 hours",
            compliant=lambda value: value is not None and value >= 1440,
            missing_scope=authenticator_client.missing_scope.get("password_policies"),
            actual_label="minimum age minutes",
        )
