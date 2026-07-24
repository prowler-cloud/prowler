from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_device_registration_laps_enabled.entra_device_registration_laps_enabled"


class Test_entra_device_registration_laps_enabled:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_device_registration_laps_enabled.entra_device_registration_laps_enabled import (
                entra_device_registration_laps_enabled,
            )

            entra_client.device_registration_policy = policy
            return entra_device_registration_laps_enabled().execute()

    def test_no_policy(self):
        assert self._run(None) == []

    def test_laps_enabled(self):
        result = self._run(DeviceRegistrationPolicy(local_admin_password_enabled=True))
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_laps_disabled(self):
        result = self._run(DeviceRegistrationPolicy(local_admin_password_enabled=False))
        assert len(result) == 1
        assert result[0].status == "FAIL"
