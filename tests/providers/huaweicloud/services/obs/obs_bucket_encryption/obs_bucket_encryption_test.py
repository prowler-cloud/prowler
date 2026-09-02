from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketEncryption:
    def test_encrypted_bucket_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption import (
                obs_bucket_encryption,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="encrypted-bucket",
                is_encrypted=True,
                encryption="AES256",
                region="la-south-2",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "OBS bucket encrypted-bucket has AES256 server-side encryption enabled."
            )
            assert result[0].resource_id == "encrypted-bucket"
            assert result[0].resource_name == "encrypted-bucket"
            assert result[0].region == "la-south-2"
            assert result[0].resource_arn == (
                "huaweicloud:obs:la-south-2:123456789012:bucket/encrypted-bucket"
            )

    def test_unencrypted_bucket_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption import (
                obs_bucket_encryption,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            bucket = Bucket(
                name="plain-bucket",
                is_encrypted=False,
                region="la-south-2",
            )
            obs_client.buckets = [bucket]
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "OBS bucket plain-bucket does not have default server-side encryption enabled."
            )

    def test_unknown_encryption_is_manual(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption import (
                obs_bucket_encryption,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="unknown-bucket",
                    is_encrypted=None,
                    encryption_error="AccessDenied: Access denied.",
                    region="la-south-2",
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_encryption().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == "OBS bucket unknown-bucket encryption configuration could not be determined: AccessDenied: Access denied."
            )

    def test_no_buckets(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_encryption.obs_bucket_encryption import (
                obs_bucket_encryption,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            check = obs_bucket_encryption()
            result = check.execute()

            assert len(result) == 0
