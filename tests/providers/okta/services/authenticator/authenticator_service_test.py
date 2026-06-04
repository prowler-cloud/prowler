from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.okta.okta_provider import DEFAULT_SCOPES
from prowler.providers.okta.services.authenticator.authenticator_service import (
    AUTHENTICATORS_READ_SCOPE,
    POLICIES_READ_SCOPE,
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

        async def fake_list_policies(type, after=None):
            assert type == "PASSWORD"
            assert after is None
            return ([policy], _resp({}), None)

        async def fake_list_authenticators():
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

        async def failing_policies(type, after=None):
            assert type == "PASSWORD"
            assert after is None
            return ([], _resp({}), Exception("forbidden"))

        async def failing_authenticators():
            return ([], _resp({}), Exception("forbidden"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing_policies
            mocked.list_authenticators = failing_authenticators
            mocked_client_cls.return_value = mocked
            service = Authenticator(provider)

        assert service.password_policies == {}
        assert service.authenticators == {}

    def test_paginates_password_policies(self):
        provider = set_mocked_okta_provider()
        page_1 = _sdk_password_policy("pol-1", "First")
        page_2 = _sdk_password_policy("pol-2", "Second")
        next_link = '<https://acme.okta.com/api/v1/policies?after=cursor-2>; rel="next"'
        calls = []

        async def fake_list_policies(type, after=None):
            assert type == "PASSWORD"
            calls.append(after)
            if after is None:
                return ([page_1], _resp({"link": next_link}), None)
            return ([page_2], _resp({}), None)

        async def fake_list_authenticators():
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_authenticators = fake_list_authenticators
            mocked_client_cls.return_value = mocked
            service = Authenticator(provider)

        assert calls == [None, "cursor-2"]
        assert set(service.password_policies.keys()) == {"pol-1", "pol-2"}

    @pytest.mark.parametrize(
        "missing_scope, expected_calls, expected_policies, expected_authenticators",
        [
            (
                POLICIES_READ_SCOPE,
                ["list_authenticators"],
                set(),
                {"aut-okta-verify"},
            ),
            (
                AUTHENTICATORS_READ_SCOPE,
                ["list_policies"],
                {"pol-password"},
                set(),
            ),
        ],
    )
    def test_missing_scope_skips_corresponding_sdk_call(
        self,
        missing_scope,
        expected_calls,
        expected_policies,
        expected_authenticators,
    ):
        provider = set_mocked_okta_provider(
            scopes=[scope for scope in DEFAULT_SCOPES if scope != missing_scope]
        )
        policy = _sdk_password_policy()
        okta_verify = _sdk_authenticator()
        calls = []

        async def fake_list_policies(type, after=None):
            if missing_scope == POLICIES_READ_SCOPE:
                raise AssertionError("list_policies must not be called")
            assert type == "PASSWORD"
            assert after is None
            calls.append("list_policies")
            return ([policy], _resp({}), None)

        async def fake_list_authenticators():
            if missing_scope == AUTHENTICATORS_READ_SCOPE:
                raise AssertionError("list_authenticators must not be called")
            calls.append("list_authenticators")
            return ([okta_verify], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_authenticators = fake_list_authenticators
            mocked_client_cls.return_value = mocked
            service = Authenticator(provider)

        assert service.missing_scopes == [missing_scope]
        assert set(service.password_policies.keys()) == expected_policies
        assert set(service.authenticators.keys()) == expected_authenticators
        assert calls == expected_calls
