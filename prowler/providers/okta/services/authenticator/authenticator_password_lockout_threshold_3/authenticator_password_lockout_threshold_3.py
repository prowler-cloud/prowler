from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_lockout_threshold_3(Check):
    """Ensure Okta Password Policies enforce the required STIG setting."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            field_name="max_attempts",
            requirement="password lockout after 3 or fewer failed attempts",
            compliant=lambda value: value is not None and value <= 3,
            actual_label="maximum failed attempts",
        )
