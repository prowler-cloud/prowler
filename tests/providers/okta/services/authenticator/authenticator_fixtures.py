from unittest import mock

from prowler.providers.okta.services.authenticator.authenticator_service import (
    OktaAuthenticator,
    PasswordPolicy,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_authenticator_client(
    password_policies: dict = None, authenticators: dict = None
):
    client = mock.MagicMock()
    client.password_policies = password_policies or {}
    client.authenticators = authenticators or {}
    client.provider = set_mocked_okta_provider()
    return client


def password_policy(
    policy_id: str = "pol-password",
    name: str = "Default Password Policy",
    *,
    status: str = "ACTIVE",
    priority: int = 1,
    max_attempts: int = 3,
    min_length: int = 15,
    min_upper_case: int = 1,
    min_lower_case: int = 1,
    min_number: int = 1,
    min_symbol: int = 1,
    min_age_minutes: int = 1440,
    max_age_days: int = 60,
    history_count: int = 5,
    common_password_check: bool = True,
):
    return PasswordPolicy(
        id=policy_id,
        name=name,
        status=status,
        priority=priority,
        max_attempts=max_attempts,
        min_length=min_length,
        min_upper_case=min_upper_case,
        min_lower_case=min_lower_case,
        min_number=min_number,
        min_symbol=min_symbol,
        min_age_minutes=min_age_minutes,
        max_age_days=max_age_days,
        history_count=history_count,
        common_password_check=common_password_check,
    )


def authenticator(
    auth_id: str = "aut-okta-verify",
    key: str = "okta_verify",
    name: str = "Okta Verify",
    *,
    status: str = "ACTIVE",
    fips: str = "REQUIRED",
):
    return OktaAuthenticator(
        id=auth_id,
        key=key,
        name=name,
        status=status,
        type="app",
        fips=fips,
    )
