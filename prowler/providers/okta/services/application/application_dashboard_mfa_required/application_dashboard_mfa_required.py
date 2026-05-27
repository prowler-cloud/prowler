from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)
from prowler.providers.okta.services.application.application_service import (
    DASHBOARD_APP_NAME,
)
from prowler.providers.okta.services.application.lib.application_helpers import (
    app_label,
    app_not_found_finding,
    missing_app_scope_finding,
    policy_missing_finding,
    rule_label,
    top_active_rule,
)

DASHBOARD_LABEL_HINT = "Okta Dashboard"


class application_dashboard_mfa_required(Check):
    """STIG V-273194 / OKTA-APP-000570.

    The Authentication Policy bound to the Okta Dashboard app must
    require multifactor authentication on its top rule for
    non-privileged users: `User must authenticate with` set to
    `Password / IdP + Another factor` or `Any 2 factor types`
    (`AssuranceMethod.factor_mode == "2FA"`).
    """

    def execute(self) -> list[CheckReportOkta]:
        org_domain = application_client.provider.identity.org_domain

        for scope_key in ("built_in_apps", "access_policies"):
            missing_scope = application_client.missing_scope.get(scope_key)
            if missing_scope:
                return [
                    missing_app_scope_finding(
                        self.metadata(),
                        org_domain,
                        missing_scope,
                        DASHBOARD_LABEL_HINT,
                    )
                ]

        app = application_client.built_in_apps.get(DASHBOARD_APP_NAME)
        if app is None:
            return [
                app_not_found_finding(self.metadata(), org_domain, DASHBOARD_LABEL_HINT)
            ]

        if app.access_policy_id is None or app.access_policy is None:
            return [policy_missing_finding(self.metadata(), org_domain, app)]

        report = CheckReportOkta(
            metadata=self.metadata(), resource=app, org_domain=org_domain
        )
        rule = top_active_rule(app)
        if rule is None:
            report.status = "FAIL"
            report.status_extended = (
                f"{app_label(app)} has no active rules on its Authentication "
                "Policy. The top rule must set `User must authenticate with` to "
                "`Password / IdP + Another factor` or `Any 2 factor types`."
            )
        elif rule.factor_mode == "2FA":
            report.status = "PASS"
            report.status_extended = (
                f"Top active {rule_label(rule)} on {app_label(app)} enforces "
                "multifactor authentication (`factorMode=2FA`)."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Top active {rule_label(rule)} on {app_label(app)} does not "
                f"enforce multifactor authentication "
                f"(`factorMode={rule.factor_mode or 'unset'}`). "
                "Set `User must authenticate with` to `Password / IdP + Another "
                "factor` or `Any 2 factor types`."
            )
        return [report]
