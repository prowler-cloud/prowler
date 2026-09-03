from unittest import mock

import pytest

from prowler.providers.fly.services.machine.machine_service import FlyMachine
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    MACHINE_ID,
    MACHINE_NAME,
    ORG_SLUG,
    REGION,
    set_mocked_fly_provider,
)

CHECK_MODULE = (
    "prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env."
    "machine_no_plaintext_secrets_in_env.machine_client"
)


def _machine(env: dict, secret_names: list = None) -> FlyMachine:
    return FlyMachine(
        id=MACHINE_ID,
        name=MACHINE_NAME,
        app_name=APP_NAME,
        org_slug=ORG_SLUG,
        region=REGION,
        state="started",
        image="registry.fly.io/test-app@sha256:" + "a" * 64,
        env=env,
        app_secret_names=secret_names,
    )


class Test_machine_no_plaintext_secrets_in_env:
    def test_no_machines(self):
        machine_client = mock.MagicMock
        machine_client.machines = {}
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 0

    def test_machine_without_plaintext_secrets(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {"PRIMARY_REGION": REGION, "LOG_LEVEL": "info"},
                secret_names=["DATABASE_URL", "AUTH_COOKIE_SECRET"],
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} has no secret-like values "
                f"in its plain machine configuration (2 Fly secret(s) injected)."
            )

    def test_machine_with_plaintext_secrets(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {"POSTGRES_PASSWORD": "hunter2", "API_KEY": "abc", "LOG_LEVEL": "info"}
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} exposes secret-like values "
                f"in its plain machine configuration: API_KEY, POSTGRES_PASSWORD."
            )

    def test_endpoint_url_is_not_a_plaintext_secret(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {
                    "TOKEN_ISSUER_URL": "https://issuer.example.com/oauth/token",
                    "CREDENTIAL_ISSUER_URL": "https://issuer.example.com/.well-known/jwks.json",
                }
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_url_carrying_a_credential_is_a_plaintext_secret(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {
                    "TOKEN_ENDPOINT_URL": "https://issuer.example.com/token?access_token=abc",
                    "API_KEY_URL": "https://user:pass@issuer.example.com/keys",
                    "PRIVATE_KEY_PATH": "/etc/keys/service.pem",
                }
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.endswith(
                "API_KEY_URL, PRIVATE_KEY_PATH, TOKEN_ENDPOINT_URL."
            )

    def test_configured_patterns_are_honoured(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine({"POSTGRES_PASSWORD": "hunter2", "SEED": "1234"})
        }
        machine_client.audit_config = {"secret_env_name_patterns": ["SEED"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "SEED" in result[0].status_extended
            assert "POSTGRES_PASSWORD" not in result[0].status_extended

    def test_url_with_embedded_path_credential_is_a_plaintext_secret(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {
                    "WEBHOOK_SECRET_URL": "https://hooks.example.com/services/T0AB1CD2E/B0AB1CD2E/aBcDeFgHiJkLmNoPqRsTuVwX",
                    "TOKEN_LOOKUP_URL": "https://api.example.com/token/abc123def456",
                    "TOKEN_ROTATE_URL": "https://api.example.com/keys/rotate",
                }
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.endswith(
                "TOKEN_LOOKUP_URL, WEBHOOK_SECRET_URL."
            )

    def test_url_with_unlisted_credential_parameter_is_a_plaintext_secret(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                {
                    "TOKEN_ENDPOINT_URL": "https://issuer.example.com/token?client_secret=abc",
                    "API_KEY_ENDPOINT": "https://api.example.com/v1/data?x-api-key=abc",
                    "SECRET_CALLBACK_URL": "https://example.com/callback#access_token=abc",
                    "TOKEN_SEARCH_URL": "https://example.com/search?keyword=prowler&state=1",
                }
            )
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.endswith(
                "API_KEY_ENDPOINT, SECRET_CALLBACK_URL, TOKEN_ENDPOINT_URL."
            )

    def test_unknown_secret_names_are_reported_as_unknown(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine({"LOG_LEVEL": "info"}, secret_names=None)
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended.endswith(
                "(Fly secret names could not be read)."
            )

    def test_no_secrets_set_are_counted(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine({"LOG_LEVEL": "info"}, secret_names=[])
        }
        machine_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended.endswith("(0 Fly secret(s) injected).")

    def test_null_patterns_config_uses_defaults(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine({"POSTGRES_PASSWORD": "hunter2"})
        }
        machine_client.audit_config = {"secret_env_name_patterns": None}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                machine_no_plaintext_secrets_in_env,
            )

            check = machine_no_plaintext_secrets_in_env()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "POSTGRES_PASSWORD" in result[0].status_extended


class Test_is_credential_free_url:
    @pytest.fixture(autouse=True)
    def _load(self):
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_fly_provider(),
        ):
            from prowler.providers.fly.services.machine.machine_no_plaintext_secrets_in_env.machine_no_plaintext_secrets_in_env import (
                is_credential_free_url,
            )

        self.is_credential_free_url = is_credential_free_url

    @pytest.mark.parametrize(
        "value",
        [
            "https://issuer.example.com/oauth/token",
            "https://issuer.example.com/.well-known/jwks.json",
            "https://issuer.example.com/.well-known/openid-configuration",
            "https://issuer.example.com/tenants/3f2504e0-4f89-11d3-9a0c-0305e82c3301/oauth2/token",
            "https://api.example.com:8443/v1/keys",
            "https://api.example.com/keys/rotate",
            "https://example.com/callback?state=1",
            "https://example.com/search?keyword=prowler",
            "http://[2001:db8::1]:8080/health",
            "https://auth.example.com/auth/v1/token",
            "https://api.example.com/auth/v2/login",
            "https://api.example.com/token/v2",
            "https://api.example.com/2024-01-01/token",
            "https://example.com/callback?user=1&state=xyz",
            "https://login.example.com/oauth?tenant=contoso-prod-eu-west-1",
            "https://api.example.com/?utm_source=newsletter2024&utm_medium=email",
            "https://api.example.com/?next=https://portal.example.com/dashboard",
            "https://api.example.com/customer-portal-v2-2024-eu/health",
        ],
    )
    def test_bare_endpoint_urls_are_credential_free(self, value):
        assert self.is_credential_free_url(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "https://user:pass@issuer.example.com/keys",
            "https://issuer.example.com/token?access_token=abc",
            "https://issuer.example.com/token?client_secret=abc",
            "https://api.example.com/v1/data?x-api-key=abc",
            "https://storage.example.com/bucket/object?X-Amz-Signature=abc",
            "https://example.com/callback#access_token=abc",
            "https://hooks.example.com/services/T0AB1CD2E/B0AB1CD2E/aBcDeFgHiJkLmNoPqRsTuVwX",
            "https://api.example.com/token/abc123def456",
            "https://api.example.com/secret/mysecretvalue",
            "https://api.example.com/api_key=abc/x",
            "https://example.com/a1b2c3d4e5f6a7b8c9d0e1f2",
            "https://example.com/api?user=1&t=aBcDeFgHiJkLmNoPqRsTuVwXyZ123",
            "https://example.com/verify?jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc&x=1",
            "https://example.com/verify?x=1&y=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
            "https://api.example.com/v1;access_token=abc",
            "https://api.example.com/v1/data;token=aBcDeFgHiJkLmNoPqRsTuVwXyZ123",
            "https://example.com/login?user=admin&pwd=hunter2",
            "https://example.com/?passwd=abc",
            "https://example.com/?bearer=abc",
            "https://example.com/?session=abc",
            "https://example.com/#aBcDeFgHiJkLmNoPqRsTuVwXyZ123",
            "https://host.example.com/?x=abc/def+ghi1234567890ABCDEFGH==",
            "https://host.example.com/hook/AbC+dEf1234567890abcdefgh",
            "https://host.example.com/?sig=abc%2Fdef%2Bghi1234567890ABCDEFGH%3D%3D",
            "https://api.example.com/?next=https://admin:hunter2@internal.example.com",
            "https://api.example.com/?next=https://hooks.example.com/services/T0AB1CD2E/B0AB1CD2E/aBcDeFgHiJkLmNoPqRsTuVwX",
            "postgres://user:pw@db.internal:5432/app",
            "/etc/keys/service.pem",
            "hunter2",
            "",
        ],
    )
    def test_credential_bearing_values_are_not_credential_free(self, value):
        assert self.is_credential_free_url(value) is False

    def test_configured_patterns_extend_the_query_check(self):
        url = "https://example.com/data?seed=1234"

        assert self.is_credential_free_url(url) is True
        assert self.is_credential_free_url(url, ["SEED"]) is False
