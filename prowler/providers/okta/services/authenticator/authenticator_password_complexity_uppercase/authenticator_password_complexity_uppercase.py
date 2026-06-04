from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    execute_password_policy_check,
)


class authenticator_password_complexity_uppercase(Check):
    """Ensure Okta Password Policies enforce the required STIG setting."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        return execute_password_policy_check(
            metadata=self.metadata(),
            org_domain=authenticator_client.provider.identity.org_domain,
            password_policies=authenticator_client.password_policies,
            missing_scopes=authenticator_client.missing_scopes,
            field_name="min_upper_case",
            requirement="at least one uppercase character",
            compliant=lambda value: value is not None and value >= 1,
            actual_label="minimum uppercase characters",
        )
