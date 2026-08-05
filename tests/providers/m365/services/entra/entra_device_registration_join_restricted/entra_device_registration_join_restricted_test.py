from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationMembershipType,
    DeviceRegistrationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_device_registration_join_restricted.entra_device_registration_join_restricted"


class Test_entra_device_registration_join_restricted:
    def _run(self, policy):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_device_registration_join_restricted.entra_device_registration_join_restricted import (
                entra_device_registration_join_restricted,
            )

            entra_client.device_registration_policy = policy
            return entra_device_registration_join_restricted().execute()

    def test_no_policy(self):
        assert self._run(None) == []

    def test_all_users(self):
        result = self._run(
            DeviceRegistrationPolicy(
                azure_ad_join_allowed_to_join_type=DeviceRegistrationMembershipType.ALL.value
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "The users allowed to join devices to Microsoft Entra are not restricted to selected users or none."
        )
        assert result[0].resource_id == "deviceRegistrationPolicy"
        assert result[0].resource_name == "Device Registration Policy"

    def test_unknown_membership_type(self):
        result = self._run(
            DeviceRegistrationPolicy(azure_ad_join_allowed_to_join_type=None)
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "The users allowed to join devices to Microsoft Entra are not restricted to selected users or none."
        )

    def test_selected_users(self):
        result = self._run(
            DeviceRegistrationPolicy(
                azure_ad_join_allowed_to_join_type=DeviceRegistrationMembershipType.ENUMERATED.value
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Only selected users or no users are allowed to join devices to Microsoft Entra."
        )
        assert result[0].resource_id == "deviceRegistrationPolicy"
        assert result[0].resource_name == "Device Registration Policy"

    def test_none(self):
        result = self._run(
            DeviceRegistrationPolicy(
                azure_ad_join_allowed_to_join_type=DeviceRegistrationMembershipType.NONE.value
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Only selected users or no users are allowed to join devices to Microsoft Entra."
        )
