from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestKmsKeyRotationEnabled:
    def test_rotation_enabled_passes(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                name="rotated-key",
                is_rotation_enabled=True,
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "enabled" in result[0].status_extended

    def test_rotation_disabled_fails(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                name="static-key",
                is_rotation_enabled=False,
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have rotation enabled" in result[0].status_extended

    def test_no_keys(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_enabled.kms_key_rotation_enabled import (
                kms_key_rotation_enabled,
            )

            kms_client.keys = []
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_enabled()
            result = check.execute()

            assert len(result) == 0
