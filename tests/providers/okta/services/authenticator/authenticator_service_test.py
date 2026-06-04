from types import SimpleNamespace
from unittest import mock

from prowler.providers.okta.services.authenticator.authenticator_service import (
    Authenticator,
    OktaAuthenticator,
    PasswordPolicy,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _resp(headers: dict = None):
    return SimpleNamespace(headers=headers or {})


def _sdk_password_policy(policy_id: str = "pol-password", name: str = "Default"):
    return SimpleNamespace(
        id=policy_id,
        name=name,
        priority=1,
        status="ACTIVE",
        system=True,
        settings=SimpleNamespace(
            password=SimpleNamespace(
                lockout=SimpleNamespace(max_attempts=3),
                complexity=SimpleNamespace(
                    min_length=15,
                    min_upper_case=1,
                    min_lower_case=1,
                    min_number=1,
                    min_symbol=1,
                    dictionary=SimpleNamespace(common=True),
                ),
                age=SimpleNamespace(
                    min_age_minutes=1440,
                    max_age_days=60,
                    history_count=5,
                ),
            )
        ),
    )


def _sdk_authenticator(
    auth_id: str = "aut-okta-verify",
    key: str = "okta_verify",
    status: str = "ACTIVE",
    fips: str = "REQUIRED",
):
    return SimpleNamespace(
        id=auth_id,
        key=key,
        name="Okta Verify" if key == "okta_verify" else "Smart Card IdP",
        status=status,
        type="app",
        settings=SimpleNamespace(compliance=SimpleNamespace(fips=fips)),
    )


class Test_Authenticator_service:
    def test_fetches_password_policies_and_authenticators(self):
        provider = set_mocked_okta_provider()
        policy = _sdk_password_policy()
        okta_verify = _sdk_authenticator()

        async def fake_list_policies(*_a, **_k):
            return ([policy], _resp({}), None)

        async def fake_list_authenticators(*_a, **_k):
            return ([okta_verify], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_authenticators = fake_list_authenticators
            mocked_client_cls.return_value = mocked

            service = Authenticator(provider)

        assert isinstance(service.password_policies[policy.id], PasswordPolicy)
        assert service.password_policies[policy.id].min_length == 15
        assert isinstance(service.authenticators[okta_verify.id], OktaAuthenticator)
        assert service.authenticators[okta_verify.id].fips == "REQUIRED"

    def test_returns_empty_collections_on_api_errors(self):
        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("forbidden"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing
            mocked.list_authenticators = failing
            mocked_client_cls.return_value = mocked
            service = Authenticator(provider)

        assert service.password_policies == {}
        assert service.authenticators == {}
