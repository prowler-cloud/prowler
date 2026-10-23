from unittest import mock

from prowler.providers.m365.services.intune.intune_service import (
    DeviceEnrollmentConfiguration,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.intune.intune_device_enrollment_personal_device_restricted.intune_device_enrollment_personal_device_restricted"


class Test_intune_device_enrollment_personal_device_restricted:
    def _run(self, configurations):
        intune_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.intune.intune_device_enrollment_personal_device_restricted.intune_device_enrollment_personal_device_restricted import (
                intune_device_enrollment_personal_device_restricted,
            )

            intune_client.device_enrollment_configurations = configurations
            return intune_device_enrollment_personal_device_restricted().execute()

    def test_no_default_config(self):
        assert self._run([]) == []

    def test_all_blocked(self):
        result = self._run(
            [
                DeviceEnrollmentConfiguration(
                    id="cfg",
                    priority=0,
                    platform_restrictions={
                        "iosRestriction": True,
                        "androidRestriction": True,
                        "windowsRestriction": True,
                    },
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_one_allowed(self):
        result = self._run(
            [
                DeviceEnrollmentConfiguration(
                    id="cfg",
                    priority=0,
                    platform_restrictions={
                        "iosRestriction": True,
                        "androidRestriction": False,
                    },
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
