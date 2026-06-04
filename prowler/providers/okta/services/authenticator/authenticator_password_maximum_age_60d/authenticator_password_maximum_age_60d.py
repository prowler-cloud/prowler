from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_maximum_age_60d(Check):
    """Ensure Okta Password Policies enforce the required STIG setting."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            missing_scopes=authenticator_client.missing_scopes,
            field_name="max_age_days",
            requirement="maximum password age of 60 days or less",
            compliant=lambda value: value is not None and 0 < value <= 60,
            actual_label="maximum age days",
        )
