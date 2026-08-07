from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_sfs_file_system_encryption:
    def test_sfs_file_system_encryption_pass(self):
        sfs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption.sfs_client",
                new=sfs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption import (
                sfs_file_system_encryption,
            )
            from prowler.providers.huaweicloud.services.sfs.sfs_service import (
                SFSShare,
            )

            sfs_client.shares = [
                SFSShare(
                    share_id="sfs-001",
                    name="share-encrypted",
                    crypt_key_id="kms-key-001",
                    region="la-south-2",
                ),
            ]
            sfs_client.audited_account = "123456789012"

            check = sfs_file_system_encryption()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "sfs-001"
            assert "encryption enabled" in results[0].status_extended

    def test_sfs_file_system_encryption_fail(self):
        sfs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption.sfs_client",
                new=sfs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption import (
                sfs_file_system_encryption,
            )
            from prowler.providers.huaweicloud.services.sfs.sfs_service import (
                SFSShare,
            )

            sfs_client.shares = [
                SFSShare(
                    share_id="sfs-002",
                    name="share-unencrypted",
                    crypt_key_id="",
                    region="la-south-2",
                ),
            ]
            sfs_client.audited_account = "123456789012"

            check = sfs_file_system_encryption()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "sfs-002"
            assert "does not have encryption" in results[0].status_extended

    def test_sfs_file_system_encryption_mixed(self):
        sfs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption.sfs_client",
                new=sfs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption import (
                sfs_file_system_encryption,
            )
            from prowler.providers.huaweicloud.services.sfs.sfs_service import (
                SFSShare,
            )

            sfs_client.shares = [
                SFSShare(
                    share_id="sfs-001",
                    name="share-encrypted",
                    crypt_key_id="kms-key-001",
                    region="la-south-2",
                ),
                SFSShare(
                    share_id="sfs-002",
                    name="share-unencrypted",
                    crypt_key_id="",
                    region="la-south-2",
                ),
            ]
            sfs_client.audited_account = "123456789012"

            check = sfs_file_system_encryption()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_sfs_file_system_encryption_empty(self):
        sfs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption.sfs_client",
                new=sfs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.sfs.sfs_file_system_encryption.sfs_file_system_encryption import (
                sfs_file_system_encryption,
            )

            sfs_client.shares = []
            sfs_client.audited_account = "123456789012"

            check = sfs_file_system_encryption()
            results = check.execute()

            assert len(results) == 0
