from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodConfiguration,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_authentication_method_sms_voice_disabled:
    def test_no_configurations(self):
        """
        Test when authentication_method_configurations is empty:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {}
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_both_disabled(self):
        """
        Test when both SMS and Voice are disabled:
        The check should return two PASS findings.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "sms": AuthenticationMethodConfiguration(
                    id="sms",
                    state="disabled",
                ),
                "voice": AuthenticationMethodConfiguration(
                    id="voice",
                    state="disabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SMS authentication method is disabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "SMS Authentication Method"
            assert result[0].location == "global"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Voice authentication method is disabled in the tenant."
            )
            assert result[1].resource_id == DOMAIN
            assert result[1].resource_name == "Voice Authentication Method"
            assert result[1].location == "global"

    def test_both_enabled(self):
        """
        Test when both SMS and Voice are enabled:
        The check should return two FAIL findings.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "sms": AuthenticationMethodConfiguration(
                    id="sms",
                    state="enabled",
                ),
                "voice": AuthenticationMethodConfiguration(
                    id="voice",
                    state="enabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SMS authentication method is enabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "SMS Authentication Method"
            assert result[0].location == "global"
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Voice authentication method is enabled in the tenant."
            )
            assert result[1].resource_id == DOMAIN
            assert result[1].resource_name == "Voice Authentication Method"
            assert result[1].location == "global"

    def test_sms_enabled_voice_disabled(self):
        """
        Test when SMS is enabled and Voice is disabled:
        The check should return FAIL for SMS and PASS for Voice.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "sms": AuthenticationMethodConfiguration(
                    id="sms",
                    state="enabled",
                ),
                "voice": AuthenticationMethodConfiguration(
                    id="voice",
                    state="disabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SMS authentication method is enabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "SMS Authentication Method"
            assert result[0].location == "global"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Voice authentication method is disabled in the tenant."
            )
            assert result[1].resource_id == DOMAIN
            assert result[1].resource_name == "Voice Authentication Method"
            assert result[1].location == "global"

    def test_sms_disabled_voice_enabled(self):
        """
        Test when SMS is disabled and Voice is enabled:
        The check should return PASS for SMS and FAIL for Voice.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "sms": AuthenticationMethodConfiguration(
                    id="sms",
                    state="disabled",
                ),
                "voice": AuthenticationMethodConfiguration(
                    id="voice",
                    state="enabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SMS authentication method is disabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "SMS Authentication Method"
            assert result[0].location == "global"
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Voice authentication method is enabled in the tenant."
            )
            assert result[1].resource_id == DOMAIN
            assert result[1].resource_name == "Voice Authentication Method"
            assert result[1].location == "global"

    def test_only_sms_present(self):
        """
        Test when only SMS configuration exists (no Voice):
        The check should return one finding for SMS only.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "sms": AuthenticationMethodConfiguration(
                    id="sms",
                    state="enabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SMS authentication method is enabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "SMS Authentication Method"
            assert result[0].location == "global"

    def test_only_voice_present(self):
        """
        Test when only Voice configuration exists (no SMS):
        The check should return one finding for Voice only.
        """
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_sms_voice_disabled.entra_authentication_method_sms_voice_disabled import (
                entra_authentication_method_sms_voice_disabled,
            )

            entra_client.authentication_method_configurations = {
                "voice": AuthenticationMethodConfiguration(
                    id="voice",
                    state="disabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_sms_voice_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Voice authentication method is disabled in the tenant."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "Voice Authentication Method"
            assert result[0].location == "global"
