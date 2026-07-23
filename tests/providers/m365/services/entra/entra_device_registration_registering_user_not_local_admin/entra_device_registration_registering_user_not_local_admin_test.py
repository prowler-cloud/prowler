from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationMembershipType,
    DeviceRegistrationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_device_registration_registering_user_not_local_admin.entra_device_registration_registering_user_not_local_admin"


class Test_entra_device_registration_registering_user_not_local_admin:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_device_registration_registering_user_not_local_admin.entra_device_registration_registering_user_not_local_admin import (
                entra_device_registration_registering_user_not_local_admin,
            )

            entra_client.device_registration_policy = policy
            return (
                entra_device_registration_registering_user_not_local_admin().execute()
            )

    def test_no_policy(self):
        assert self._run(None) == []

    def test_all_registering_users(self):
        result = self._run(
            DeviceRegistrationPolicy(
                azure_ad_join_registering_users_type=DeviceRegistrationMembershipType.ALL.value
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_selected_registering_users(self):
        result = self._run(
            DeviceRegistrationPolicy(
                azure_ad_join_registering_users_type=DeviceRegistrationMembershipType.NONE.value
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
