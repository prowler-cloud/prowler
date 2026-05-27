from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)
from prowler.providers.okta.services.application.application_service import (
    AuthenticationPolicyRule,
    OktaBuiltInApp,
)
from prowler.providers.okta.services.application.lib.application_helpers import (
    active_apps,
    app_label,
    missing_integrated_apps_scope_finding,
    no_active_apps_finding,
    rule_has_network_zone,
    rule_label,
)


class application_authentication_policy_network_zone_enforced(Check):
    """STIG V-279693 / OKTA-APP-003244.

    Every active Okta application must be bound to an Authentication
    Policy that uses Network Zones. Each active non-default rule must map
    `User's IP` to an allow/deny zone, and the active Catch-all Rule
    must deny access.
    """

    def execute(self) -> list[CheckReportOkta]:
        findings: list[CheckReportOkta] = []
        org_domain = application_client.provider.identity.org_domain

        for scope_key in ("integrated_apps", "access_policies"):
            missing_scope = application_client.missing_scope.get(scope_key)
            if missing_scope:
                findings.append(
                    missing_integrated_apps_scope_finding(
                        self.metadata(),
                        org_domain,
                        missing_scope,
                    )
                )
                return findings

        apps = active_apps(application_client.integrated_apps)
        if not apps:
            findings.append(no_active_apps_finding(self.metadata(), org_domain))
            return findings

        for app in apps:
            report = CheckReportOkta(
                metadata=self.metadata(),
                resource=app,
                org_domain=org_domain,
                resource_name=app.label or app.name,
                resource_id=app.id,
            )
            status, status_extended = _evaluate_app(app)
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings


def _active_rules(app: OktaBuiltInApp) -> list[AuthenticationPolicyRule]:
    if app.access_policy is None:
        return []
    return sorted(
        [
            rule
            for rule in app.access_policy.rules
            if not rule.status or rule.status.upper() == "ACTIVE"
        ],
        key=lambda rule: (
            rule.priority if rule.priority is not None else float("inf"),
            rule.name,
        ),
    )


def _evaluate_app(app: OktaBuiltInApp) -> tuple[str, str]:
    label = app_label(app)
    if app.access_policy_id is None or app.access_policy is None:
        return (
            "FAIL",
            f"{label} has no Authentication Policy bound to it. "
            "Bind an Access Policy in Security > Authentication Policies.",
        )

    active_rules = _active_rules(app)
    if not active_rules:
        return (
            "FAIL",
            f"{label} has no active rules on its Authentication Policy. "
            "Every active non-default rule must enforce a Network Zone "
            "condition, and the Catch-all Rule must set `Access is: Denied`.",
        )

    nondefault_rules = [
        rule
        for rule in active_rules
        if not rule.is_default and rule.name != "Catch-all Rule"
    ]
    if not nondefault_rules:
        return (
            "FAIL",
            f"{label} has no active non-default rules on its Authentication "
            "Policy. Define at least one non-default rule that maps `User's "
            "IP` to a Network Zone, and use the Catch-all Rule only as the "
            "final deny path.",
        )

    missing_zone_rules = [
        rule.name for rule in nondefault_rules if not rule_has_network_zone(rule)
    ]
    if missing_zone_rules:
        quoted_rules = ", ".join(f"'{rule_name}'" for rule_name in missing_zone_rules)
        return (
            "FAIL",
            f"{label} has active non-default rule(s) without Network Zones: "
            f"{quoted_rules}. Configure `User's IP` to `In zone` or `Not in zone` "
            "for every active non-default rule.",
        )

    catch_all_rule = next(
        (
            rule
            for rule in active_rules
            if rule.is_default or rule.name == "Catch-all Rule"
        ),
        None,
    )
    if catch_all_rule is None:
        return (
            "FAIL",
            f"{label} has no active Catch-all Rule. The Catch-all Rule must "
            "deny access after the zoned non-default rules.",
        )

    if catch_all_rule.access != "DENY":
        return (
            "FAIL",
            f"Active {rule_label(catch_all_rule)} on {label} does not set "
            f"`Access is` to `DENY` (`access={catch_all_rule.access or 'unset'}`). "
            "Set the Catch-all Rule to deny access.",
        )

    return (
        "PASS",
        f"{label} applies Network Zones on every active non-default rule and "
        f"its active {rule_label(catch_all_rule)} denies access.",
    )
