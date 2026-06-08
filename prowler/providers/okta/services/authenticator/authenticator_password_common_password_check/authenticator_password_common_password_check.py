from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_common_password_check(Check):
    """STIG V-273208 / OKTA-APP-002980.

    Every active Okta Password Policy must reject passwords found in the common-password dictionary.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            field_name="common_password_check",
            requirement="common-password dictionary checks",
            compliant=lambda value: value is True,
            missing_scope=authenticator_client.missing_scope.get("password_policies"),
            actual_label="common password check enabled",
        )
