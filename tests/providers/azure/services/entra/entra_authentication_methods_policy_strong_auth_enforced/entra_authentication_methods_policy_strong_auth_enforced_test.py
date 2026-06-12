from unittest import mock

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_authentication_methods_policy_strong_auth_enforced:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )

            entra_client.authentication_methods_policy = {}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 0

    def test_entra_policy_none(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )

            entra_client.authentication_methods_policy = {DOMAIN: None}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 0

    def test_entra_registration_enabled_strong_method_enabled(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthMethodConfig,
                AuthMethodsPolicy,
            )

            policy = AuthMethodsPolicy(
                id="authMethodsPolicy",
                registration_enforcement_state="enabled",
                method_configurations=[
                    AuthMethodConfig(
                        id="MicrosoftAuthenticator",
                        method_name="microsoftAuthenticator",
                        state="enabled",
                    ),
                    AuthMethodConfig(
                        id="Sms",
                        method_name="sms",
                        state="enabled",
                    ),
                ],
            )
            entra_client.authentication_methods_policy = {DOMAIN: policy}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert "registration campaign is enabled" in result[0].status_extended
            assert result[1].status == "PASS"
            assert "microsoftAuthenticator" in result[1].status_extended

    def test_entra_registration_disabled_no_strong_methods(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthMethodConfig,
                AuthMethodsPolicy,
            )

            policy = AuthMethodsPolicy(
                id="authMethodsPolicy",
                registration_enforcement_state="disabled",
                method_configurations=[
                    AuthMethodConfig(
                        id="Sms",
                        method_name="sms",
                        state="enabled",
                    ),
                    AuthMethodConfig(
                        id="Voice",
                        method_name="voice",
                        state="enabled",
                    ),
                ],
            )
            entra_client.authentication_methods_policy = {DOMAIN: policy}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended
            assert result[1].status == "FAIL"
            assert "No strong authentication methods" in result[1].status_extended

    def test_entra_registration_disabled_strong_method_enabled(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthMethodConfig,
                AuthMethodsPolicy,
            )

            policy = AuthMethodsPolicy(
                id="authMethodsPolicy",
                registration_enforcement_state="disabled",
                method_configurations=[
                    AuthMethodConfig(
                        id="Fido2",
                        method_name="fido2",
                        state="enabled",
                    ),
                ],
            )
            entra_client.authentication_methods_policy = {DOMAIN: policy}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 2
            # Registration FAIL, but strong method PASS
            assert result[0].status == "FAIL"
            assert result[1].status == "PASS"
            assert "fido2" in result[1].status_extended

    def test_entra_multiple_strong_methods(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_authentication_methods_policy_strong_auth_enforced.entra_authentication_methods_policy_strong_auth_enforced import (
                entra_authentication_methods_policy_strong_auth_enforced,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthMethodConfig,
                AuthMethodsPolicy,
            )

            policy = AuthMethodsPolicy(
                id="authMethodsPolicy",
                registration_enforcement_state="enabled",
                method_configurations=[
                    AuthMethodConfig(
                        id="MicrosoftAuthenticator",
                        method_name="microsoftAuthenticator",
                        state="enabled",
                    ),
                    AuthMethodConfig(
                        id="Fido2",
                        method_name="fido2",
                        state="enabled",
                    ),
                    AuthMethodConfig(
                        id="x509",
                        method_name="x509Certificate",
                        state="enabled",
                    ),
                ],
            )
            entra_client.authentication_methods_policy = {DOMAIN: policy}

            check = entra_authentication_methods_policy_strong_auth_enforced()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "PASS"
            assert "microsoftAuthenticator" in result[1].status_extended
            assert "fido2" in result[1].status_extended
