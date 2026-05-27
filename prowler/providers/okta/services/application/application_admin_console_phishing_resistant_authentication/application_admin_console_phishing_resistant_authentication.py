from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)
from prowler.providers.okta.services.application.application_service import (
    ADMIN_CONSOLE_APP_NAME,
)
from prowler.providers.okta.services.application.lib.application_helpers import (
    app_label,
    app_not_found_finding,
    missing_app_scope_finding,
    policy_missing_finding,
    rule_label,
    top_active_rule,
)

ADMIN_CONSOLE_LABEL_HINT = "Okta Admin Console"


class application_admin_console_phishing_resistant_authentication(Check):
    """STIG V-273191 / OKTA-APP-000190.

    The Authentication Policy bound to the Okta Admin Console app must
    restrict possession factors to phishing-resistant authenticators.
    The underlying SDK exposes `phishingResistant` on each
    `PossessionConstraint`; at least one constraint object on the top
    rule must set `phishingResistant=REQUIRED` (constraints are OR-ed
    by Okta semantics).
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
                        ADMIN_CONSOLE_LABEL_HINT,
                    )
                ]

        app = application_client.built_in_apps.get(ADMIN_CONSOLE_APP_NAME)
        if app is None:
            return [
                app_not_found_finding(
                    self.metadata(), org_domain, ADMIN_CONSOLE_LABEL_HINT
                )
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
                "Policy. STIG V-273191 requires the top rule to mark "
                "`Possession factor constraints are: Phishing resistant`."
            )
        elif rule.possession_phishing_resistant_required:
            report.status = "PASS"
            report.status_extended = (
                f"Top active {rule_label(rule)} on {app_label(app)} enforces "
                "phishing-resistant possession factors "
                "(`possession.phishingResistant=REQUIRED`)."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Top active {rule_label(rule)} on {app_label(app)} does not "
                "enforce phishing-resistant possession factors. Enable "
                "`Possession factor constraints are: Phishing resistant` "
                "on the rule."
            )
        return [report]
