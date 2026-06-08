from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_complexity_uppercase(Check):
    """STIG V-273196 / OKTA-APP-000670.

    Every active Okta Password Policy must require at least one uppercase character.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            field_name="min_upper_case",
            requirement="at least one uppercase character",
            compliant=lambda value: value is not None and value >= 1,
            missing_scope=authenticator_client.missing_scope.get("password_policies"),
            actual_label="minimum uppercase characters",
        )
