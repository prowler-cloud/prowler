from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodConfiguration,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_authentication_method_email_otp_disabled:
    def test_no_configurations(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled import (
                entra_authentication_method_email_otp_disabled,
            )

            entra_client.authentication_method_configurations = {}
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_email_otp_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_email_otp_enabled(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled import (
                entra_authentication_method_email_otp_disabled,
            )

            entra_client.authentication_method_configurations = {
                "Email": AuthenticationMethodConfiguration(
                    id="Email",
                    state="enabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_email_otp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Email OTP authentication method is enabled in the tenant."
            )

    def test_email_otp_disabled(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled import (
                entra_authentication_method_email_otp_disabled,
            )

            entra_client.authentication_method_configurations = {
                "Email": AuthenticationMethodConfiguration(
                    id="Email",
                    state="disabled",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_email_otp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Email OTP authentication method is disabled in the tenant."
            )

    def test_email_otp_unknown_state(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_email_otp_disabled.entra_authentication_method_email_otp_disabled import (
                entra_authentication_method_email_otp_disabled,
            )

            entra_client.authentication_method_configurations = {
                "Email": AuthenticationMethodConfiguration(
                    id="Email",
                    state="unknown",
                ),
            }
            entra_client.tenant_domain = DOMAIN

            check = entra_authentication_method_email_otp_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Email OTP authentication method state could not be determined; "
                "treating as enabled/non-compliant."
            )
