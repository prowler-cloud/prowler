from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestIamRootHardwareMfaEnabled:
    def test_root_with_mfa_passes(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import (
                IAMUser,
                MFADevice,
            )

            root_user = IAMUser(
                id="123456789012",
                name="root",
                is_domain_owner=True,
            )
            mfa_device = MFADevice(
                serial_number="mfa-1",
                user_id="123456789012",
            )
            iam_client.users = [root_user]
            iam_client.mfa_devices = [mfa_device]
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "MFA enabled" in result[0].status_extended

    def test_root_without_mfa_fails(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import IAMUser

            root_user = IAMUser(
                id="123456789012",
                name="root",
                is_domain_owner=True,
            )
            iam_client.users = [root_user]
            iam_client.mfa_devices = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have MFA enabled" in result[0].status_extended

    def test_no_root_user(self):
        iam_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )
            from prowler.providers.huaweicloud.services.iam.iam_service import IAMUser

            regular_user = IAMUser(
                id="user-1",
                name="regular-user",
                is_domain_owner=False,
            )
            iam_client.users = [regular_user]
            iam_client.mfa_devices = []
            iam_client.audited_account = "123456789012"
            iam_client.region = "la-south-2"

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()

            assert len(result) == 0
