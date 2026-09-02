from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestKmsKeyRotationPeriod:
    def test_rotation_enabled_with_period_passes(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period import (
                kms_key_rotation_period,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                alias="alias/rotated-key",
                is_rotation_enabled=True,
                rotation_period="30d",
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "30d" in result[0].status_extended

    def test_rotation_enabled_without_period_fails(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period import (
                kms_key_rotation_period,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                alias="alias/bad-key",
                is_rotation_enabled=True,
                rotation_period="",
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no rotation period" in result[0].status_extended

    def test_rotation_disabled_passes(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_rotation_period.kms_key_rotation_period import (
                kms_key_rotation_period,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                alias="alias/static-key",
                is_rotation_enabled=False,
                rotation_period="",
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_rotation_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not applicable" in result[0].status_extended
