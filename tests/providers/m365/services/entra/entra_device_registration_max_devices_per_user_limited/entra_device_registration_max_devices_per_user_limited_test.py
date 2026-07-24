from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_device_registration_max_devices_per_user_limited.entra_device_registration_max_devices_per_user_limited"


class Test_entra_device_registration_max_devices_per_user_limited:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_device_registration_max_devices_per_user_limited.entra_device_registration_max_devices_per_user_limited import (
                entra_device_registration_max_devices_per_user_limited,
            )

            entra_client.device_registration_policy = policy
            return entra_device_registration_max_devices_per_user_limited().execute()

    def test_no_policy(self):
        assert self._run(None) == []

    def test_within_limit(self):
        result = self._run(DeviceRegistrationPolicy(user_device_quota=10))
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_exceeds_limit(self):
        result = self._run(DeviceRegistrationPolicy(user_device_quota=50))
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_none_quota(self):
        result = self._run(DeviceRegistrationPolicy(user_device_quota=None))
        assert len(result) == 1
        assert result[0].status == "FAIL"
