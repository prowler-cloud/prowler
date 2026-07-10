from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEvsVolumeEncryption:
    def test_encrypted_volume_passes(self):
        evs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption.evs_client",
                new=evs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption import (
                evs_volume_encryption,
            )
            from prowler.providers.huaweicloud.services.evs.evs_service import Volume

            volume = Volume(
                id="vol-1",
                name="encrypted-vol",
                is_encrypted=True,
                kms_key_id="kms-key-1",
                region="la-south-2",
            )
            evs_client.volumes = [volume]
            evs_client.audited_account = "123456789012"

            check = evs_volume_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "encrypted" in result[0].status_extended

    def test_unencrypted_volume_fails(self):
        evs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption.evs_client",
                new=evs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption import (
                evs_volume_encryption,
            )
            from prowler.providers.huaweicloud.services.evs.evs_service import Volume

            volume = Volume(
                id="vol-1",
                name="plain-vol",
                is_encrypted=False,
                region="la-south-2",
            )
            evs_client.volumes = [volume]
            evs_client.audited_account = "123456789012"

            check = evs_volume_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not encrypted" in result[0].status_extended

    def test_no_volumes(self):
        evs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption.evs_client",
                new=evs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.evs.evs_volume_encryption.evs_volume_encryption import (
                evs_volume_encryption,
            )

            evs_client.volumes = []
            evs_client.audited_account = "123456789012"

            check = evs_volume_encryption()
            result = check.execute()

            assert len(result) == 0
