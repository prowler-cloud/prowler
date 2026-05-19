"""Shared helpers for `signon` service check tests.

The original idle-timeout check test file defined these helpers locally;
they were extracted here so the four checks added on top of the same
service (`signon_global_session_lifetime_18h`,
`signon_global_session_cookies_not_persistent`,
`signon_global_session_policy_network_zone_enforced`,
`signon_dod_warning_banner_configured`) can reuse them without copy-paste.
"""

from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
    SignInPage,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_signon_client(
    policies: dict = None,
    audit_config: dict = None,
    sign_in_pages: dict = None,
):
    client = mock.MagicMock()
    client.global_session_policies = policies or {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = audit_config or {}
    client.sign_in_pages = sign_in_pages or {}
    return client


def default_policy(rules):
    return GlobalSessionPolicy(
        id="pol-default",
        name="Default Policy",
        priority=99,
        status="ACTIVE",
        is_default=True,
        rules=rules,
    )


def custom_policy(rules, name: str = "Admins Policy"):
    return GlobalSessionPolicy(
        id="pol-custom",
        name=name,
        priority=1,
        status="ACTIVE",
        is_default=False,
        rules=rules,
    )


def default_rule(
    idle_min: int = 480,
    lifetime_min: int = None,
    use_persistent_cookie: bool = None,
    priority: int = 2,
    status: str = "ACTIVE",
):
    return GlobalSessionPolicyRule(
        id="rule-default",
        name="Default Rule",
        priority=priority,
        status=status,
        is_default=True,
        max_session_idle_minutes=idle_min,
        max_session_lifetime_minutes=lifetime_min,
        use_persistent_cookie=use_persistent_cookie,
    )


def non_default_rule(
    name: str,
    *,
    idle_min: int = None,
    lifetime_min: int = None,
    use_persistent_cookie: bool = None,
    network_zones_include: list = None,
    network_zones_exclude: list = None,
    priority: int = 1,
    status: str = "ACTIVE",
):
    return GlobalSessionPolicyRule(
        id=f"rule-{name.lower().replace(' ', '-')}",
        name=name,
        priority=priority,
        status=status,
        is_default=False,
        max_session_idle_minutes=idle_min,
        max_session_lifetime_minutes=lifetime_min,
        use_persistent_cookie=use_persistent_cookie,
        network_zones_include=network_zones_include or [],
        network_zones_exclude=network_zones_exclude or [],
    )


def sign_in_page(
    brand_id: str = "brand-1",
    brand_name: str = "Default Brand",
    is_customized: bool = True,
    page_content: str = None,
    fetch_error: str = None,
):
    return SignInPage(
        brand_id=brand_id,
        brand_name=brand_name,
        is_customized=is_customized,
        page_content=page_content,
        fetch_error=fetch_error,
    )


# Two distinctive marker phrases from the DTM-08-060 banner — enough to
# meet the check's MIN_MARKER_MATCHES=2 threshold without reproducing the
# full ~1300-char banner verbatim in tests.
DOD_BANNER_HTML_SNIPPET = (
    "<div>You are accessing a U.S. Government (USG) Information System "
    "(IS) that is provided for USG-authorized use only. "
    "Communications using, or data stored on, this IS may be intercepted, "
    "searched, monitored, and recorded.</div>"
)
