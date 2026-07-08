"""Shared helpers for `application` service check tests.

Mirrors `signon_fixtures.py`. The four authentication-policy checks
(MFA + phishing-resistant for Okta Admin Console and Okta Dashboard)
and the Admin Console idle-timeout check all consume the same client
shape, so the helpers stay close to the signon equivalents.
"""

from unittest import mock

from prowler.providers.okta.services.application.application_service import (
    ADMIN_CONSOLE_APP_NAME,
    DASHBOARD_APP_NAME,
    AdminConsoleAppSettings,
    AuthenticationPolicy,
    AuthenticationPolicyRule,
    OktaBuiltInApp,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_application_client(
    admin_console_settings: AdminConsoleAppSettings = None,
    built_in_apps: dict = None,
    integrated_apps: dict = None,
    audit_config: dict = None,
    missing_scope: dict = None,
):
    client = mock.MagicMock()
    client.admin_console_app_settings = admin_console_settings
    client.built_in_apps = built_in_apps or {}
    client.integrated_apps = integrated_apps or {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = audit_config or {}
    # Default to "all scopes granted" so existing tests keep working.
    client.missing_scope = missing_scope or {
        "admin_console_app_settings": None,
        "built_in_apps": None,
        "integrated_apps": None,
        "access_policies": None,
    }
    return client


def admin_console_settings(
    idle_timeout: int = None,
    max_lifetime: int = None,
) -> AdminConsoleAppSettings:
    return AdminConsoleAppSettings(
        session_idle_timeout_minutes=idle_timeout,
        session_max_lifetime_minutes=max_lifetime,
    )


def auth_policy_rule(
    name: str = "Catch-all Rule",
    *,
    priority: int = 1,
    status: str = "ACTIVE",
    is_default: bool = False,
    factor_mode: str = None,
    phishing_resistant: bool = False,
    constraints_count: int = 0,
    verification_method_type: str = "ASSURANCE",
    access: str = "ALLOW",
    network_connection: str = None,
    network_zones_include: list[str] = None,
    network_zones_exclude: list[str] = None,
):
    return AuthenticationPolicyRule(
        id=f"rule-{name.lower().replace(' ', '-')}",
        name=name,
        priority=priority,
        status=status,
        is_default=is_default,
        factor_mode=factor_mode,
        possession_phishing_resistant_required=phishing_resistant,
        constraints_count=constraints_count,
        verification_method_type=verification_method_type,
        access=access,
        network_connection=network_connection,
        network_zones_include=network_zones_include or [],
        network_zones_exclude=network_zones_exclude or [],
    )


def catch_all_rule(
    priority: int = 2,
    *,
    factor_mode: str = None,
    phishing_resistant: bool = False,
    access: str = "ALLOW",
    network_connection: str = None,
    network_zones_include: list[str] = None,
    network_zones_exclude: list[str] = None,
):
    return auth_policy_rule(
        name="Catch-all Rule",
        priority=priority,
        is_default=True,
        factor_mode=factor_mode,
        phishing_resistant=phishing_resistant,
        access=access,
        network_connection=network_connection,
        network_zones_include=network_zones_include,
        network_zones_exclude=network_zones_exclude,
    )


def admin_console_app(
    rules: list = None,
    *,
    access_policy_id: str = "rstadminconsole",
    label: str = "Okta Admin Console",
    status: str = "ACTIVE",
):
    policy = (
        AuthenticationPolicy(id=access_policy_id, rules=rules or [])
        if access_policy_id is not None
        else None
    )
    return OktaBuiltInApp(
        id="0oaadminconsole",
        name=ADMIN_CONSOLE_APP_NAME,
        label=label,
        status=status,
        access_policy_id=access_policy_id,
        access_policy=policy,
    )


def dashboard_app(
    rules: list = None,
    *,
    access_policy_id: str = "rstdashboard",
    label: str = "Okta Dashboard",
    status: str = "ACTIVE",
):
    policy = (
        AuthenticationPolicy(id=access_policy_id, rules=rules or [])
        if access_policy_id is not None
        else None
    )
    return OktaBuiltInApp(
        id="0oadashboard",
        name=DASHBOARD_APP_NAME,
        label=label,
        status=status,
        access_policy_id=access_policy_id,
        access_policy=policy,
    )


def integrated_app(
    app_id: str,
    name: str,
    *,
    rules: list = None,
    access_policy_id: str = "rstapp",
    label: str = "",
    status: str = "ACTIVE",
):
    policy = (
        AuthenticationPolicy(id=access_policy_id, rules=rules or [])
        if access_policy_id is not None
        else None
    )
    return OktaBuiltInApp(
        id=app_id,
        name=name,
        label=label or name,
        status=status,
        access_policy_id=access_policy_id,
        access_policy=policy,
    )
