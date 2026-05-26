"""Shared helpers for the OKTA application STIG checks."""

from typing import Optional

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.application.application_service import (
    AdminConsoleAppSettings,
    AuthenticationPolicyRule,
    OktaBuiltInApp,
)


def active_apps(apps: dict[str, OktaBuiltInApp]) -> list[OktaBuiltInApp]:
    """Return active apps sorted by label/name, id as tiebreaker."""
    return sorted(
        [
            app
            for app in apps.values()
            if not app.status or app.status.upper() == "ACTIVE"
        ],
        key=lambda app: (app.label or app.name, app.id),
    )


def priority_one_active_rule(
    app: OktaBuiltInApp,
) -> Optional[AuthenticationPolicyRule]:
    """Return the app's Authentication Policy Priority 1 active rule, or None.

    Mirrors `signon_helpers.priority_one_active_rule`. Inactive rules
    are skipped before priority ranking; the candidate must sit at
    `priority == 1` (the STIG fix text targets "the top rule").
    """
    if app.access_policy is None:
        return None
    active_rules = sorted(
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
    if not active_rules:
        return None
    candidate = active_rules[0]
    if candidate.priority != 1:
        return None
    return candidate


def app_label(app: OktaBuiltInApp) -> str:
    """Format a human-readable label for an Okta application."""
    label = app.label or app.name
    return f"Okta app '{label}' (app={app.name}, id={app.id})"


def rule_label(rule: AuthenticationPolicyRule) -> str:
    """Format whether a rule is the built-in catch-all or a custom rule."""
    if rule.is_default or rule.name == "Catch-all Rule":
        return f"built-in Catch-all Rule '{rule.name}'"
    return f"non-default rule '{rule.name}'"


def rule_has_network_zone(rule: AuthenticationPolicyRule) -> bool:
    """Return True when the rule maps User's IP to at least one Network Zone."""
    return bool(rule.network_zones_include or rule.network_zones_exclude)


_SCOPE_ADVICE = (
    "Grant it on the service app's Okta API Scopes tab in the Okta Admin "
    "Console, then re-run the check."
)


def missing_app_scope_finding(
    metadata, org_domain: str, scope: str, app_label_hint: str
) -> CheckReportOkta:
    """Build the MANUAL finding when an app/policy scope is not granted."""
    placeholder = OktaBuiltInApp(
        id="okta-built-in-app-scope-missing",
        name="(scope not granted)",
        label=app_label_hint,
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not evaluate the authentication policy for {app_label_hint}: "
        f"the Okta service app is missing the required `{scope}` API scope. "
        f"{_SCOPE_ADVICE}"
    )
    return report


def missing_integrated_apps_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding when the integrated-app inventory scope is not granted."""
    placeholder = OktaBuiltInApp(
        id="okta-integrated-apps-scope-missing",
        name="(scope not granted)",
        label="Okta integrated applications",
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata,
        resource=placeholder,
        org_domain=org_domain,
        resource_name=placeholder.label,
        resource_id=placeholder.id,
    )
    report.status = "MANUAL"
    report.status_extended = (
        "Could not retrieve Okta integrated applications and their "
        f"authentication policies: the Okta service app is missing the "
        f"required `{scope}` API scope. {_SCOPE_ADVICE}"
    )
    return report


def missing_admin_console_settings_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding for the Admin Console idle timeout check when scope is missing."""
    placeholder = AdminConsoleAppSettings()
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        "Could not retrieve the Okta Admin Console first-party app settings: "
        f"the Okta service app is missing the required `{scope}` API scope. "
        f"{_SCOPE_ADVICE}"
    )
    return report


def app_not_found_finding(
    metadata, org_domain: str, app_label_hint: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when a built-in OIN app isn't returned.

    Okta filters the first-party apps (`saasure`, `okta_enduser`) out of
    `/api/v1/apps` for every admin role below Super Administrator, so the
    check has no way to resolve the app's bound Authentication Policy.
    """
    placeholder = OktaBuiltInApp(
        id="okta-built-in-app-missing",
        name="(app not found)",
        label=app_label_hint,
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"The {app_label_hint} first-party app was not returned by the Okta "
        "API. Okta restricts the visibility of first-party apps "
        "(`saasure`, `okta_enduser`) to the Super Administrator role; "
        "every other role — including Read-Only Administrator — receives "
        "an empty result. Assign Super Administrator to the service app "
        "to evaluate this check."
    )
    return report


def no_active_apps_finding(metadata, org_domain: str) -> CheckReportOkta:
    """Build the MANUAL finding emitted when no active apps are returned."""
    placeholder = OktaBuiltInApp(
        id="okta-apps-missing",
        name="(no active apps)",
        label="Okta applications",
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata,
        resource=placeholder,
        org_domain=org_domain,
        resource_name=placeholder.label,
        resource_id=placeholder.id,
    )
    report.status = "MANUAL"
    report.status_extended = (
        "No active Okta applications were returned by the API. Verify the "
        "tenant exposes applications to the Read-Only Administrator role and "
        "review the application inventory manually for STIG V-279693."
    )
    return report


def policy_missing_finding(
    metadata, org_domain: str, app: OktaBuiltInApp
) -> CheckReportOkta:
    """Build the FAIL finding when the built-in app has no bound Access Policy."""
    report = CheckReportOkta(metadata=metadata, resource=app, org_domain=org_domain)
    report.status = "FAIL"
    report.status_extended = (
        f"{app_label(app)} has no Authentication Policy bound to it. "
        "Bind an Access Policy in Security > Authentication Policies."
    )
    return report
