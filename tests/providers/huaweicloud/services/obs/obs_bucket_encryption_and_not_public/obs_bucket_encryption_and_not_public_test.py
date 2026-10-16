from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketEncryptionAndNotPublic:
    def test_encrypted_private_bucket_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public import (
                obs_bucket_encryption_and_not_public,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="good-bucket",
                region="la-south-2",
                is_encrypted=True,
                is_public=False,
                acl="private",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption_and_not_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "encrypted and not publicly accessible" in result[0].status_extended

    def test_unencrypted_private_bucket_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public import (
                obs_bucket_encryption_and_not_public,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="unencrypted-bucket",
                region="la-south-2",
                is_encrypted=False,
                is_public=False,
                acl="private",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption_and_not_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not encrypted" in result[0].status_extended

    def test_encrypted_public_bucket_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public import (
                obs_bucket_encryption_and_not_public,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="public-bucket",
                region="la-south-2",
                is_encrypted=True,
                is_public=True,
                acl="public-read",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption_and_not_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "publicly accessible" in result[0].status_extended

    def test_unencrypted_public_bucket_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public import (
                obs_bucket_encryption_and_not_public,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="bad-bucket",
                region="la-south-2",
                is_encrypted=False,
                is_public=True,
                acl="public-read",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption_and_not_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not encrypted" in result[0].status_extended
            assert "publicly accessible" in result[0].status_extended

    def test_no_buckets(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption_and_not_public.obs_bucket_encryption_and_not_public import (
                obs_bucket_encryption_and_not_public,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption_and_not_public()
            result = check.execute()

            assert len(result) == 0
