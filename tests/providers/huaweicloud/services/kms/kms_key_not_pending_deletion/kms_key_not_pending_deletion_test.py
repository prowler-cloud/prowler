from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestKmsKeyNotPendingDeletion:
    def test_key_active_passes(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion import (
                kms_key_not_pending_deletion,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                alias="alias/key-1",
                state="1",
                is_rotation_enabled=False,
                rotation_period=0,
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_not_pending_deletion()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not in pending deletion state" in result[0].status_extended

    def test_key_pending_deletion_fails(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion import (
                kms_key_not_pending_deletion,
            )
            from prowler.providers.huaweicloud.services.kms.kms_service import KMSKey

            key = KMSKey(
                id="key-1",
                alias="alias/key-1",
                state="4",
                is_rotation_enabled=False,
                rotation_period=0,
                region="la-south-2",
            )
            kms_client.keys = [key]
            kms_client.audited_account = "123456789012"

            check = kms_key_not_pending_deletion()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "pending deletion state" in result[0].status_extended

    def test_no_keys(self):
        kms_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.kms.kms_key_not_pending_deletion.kms_key_not_pending_deletion import (
                kms_key_not_pending_deletion,
            )

            kms_client.keys = []
            kms_client.audited_account = "123456789012"

            check = kms_key_not_pending_deletion()
            result = check.execute()

            assert len(result) == 0
