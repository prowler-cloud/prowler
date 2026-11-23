from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketAclEveryoneAccess:
    def test_bucket_acl_private_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access import (
                obs_bucket_acl_everyone_access,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="private-acl-bucket",
                    region="cn-north-4",
                    acl_everyone_permissions=[],
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_acl_everyone_access().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "does not grant ACL permissions to Everyone"
                in result[0].status_extended
            )

    def test_bucket_acl_everyone_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access import (
                obs_bucket_acl_everyone_access,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="everyone-acl-bucket",
                    region="cn-north-4",
                    acl_everyone_permissions=["READ", "WRITE"],
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_acl_everyone_access().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "grants ACL permissions (READ, WRITE) to Everyone"
                in result[0].status_extended
            )

    def test_bucket_acl_unknown_skipped(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_acl_everyone_access.obs_bucket_acl_everyone_access import (
                obs_bucket_acl_everyone_access,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="unknown-acl-bucket",
                    region="cn-north-4",
                    acl_everyone_permissions=None,
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_acl_everyone_access().execute()

            assert len(result) == 0
