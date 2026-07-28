from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_device_registration_global_admins_not_local_admins.entra_device_registration_global_admins_not_local_admins"


class Test_entra_device_registration_global_admins_not_local_admins:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_device_registration_global_admins_not_local_admins.entra_device_registration_global_admins_not_local_admins import (
                entra_device_registration_global_admins_not_local_admins,
            )

            entra_client.device_registration_policy = policy
            return entra_device_registration_global_admins_not_local_admins().execute()

    def test_no_policy(self):
        assert self._run(None) == []

    def test_global_admins_enabled(self):
        result = self._run(
            DeviceRegistrationPolicy(azure_ad_join_global_admins_enabled=True)
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_global_admins_disabled(self):
        result = self._run(
            DeviceRegistrationPolicy(azure_ad_join_global_admins_enabled=False)
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
