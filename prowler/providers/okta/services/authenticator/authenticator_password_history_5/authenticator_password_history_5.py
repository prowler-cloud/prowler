from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_history_5(Check):
    """STIG V-273209 / OKTA-APP-003010.

    Every active Okta Password Policy must remember at least the last 5 previous passwords.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            field_name="history_count",
            requirement="password history of at least 5 previous passwords",
            compliant=lambda value: value is not None and value >= 5,
            missing_scope=authenticator_client.missing_scope.get("password_policies"),
            actual_label="password history count",
        )
