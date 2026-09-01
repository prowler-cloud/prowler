from unittest import mock

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
        app_secret_names=secret_names or [],
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
