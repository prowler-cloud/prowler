from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketCorsWildcardOrigin:
    def test_no_resources(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin import (
                obs_bucket_cors_wildcard_origin,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            result = obs_bucket_cors_wildcard_origin().execute()
            assert len(result) == 0

    def test_bucket_restricted_cors_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin import (
                obs_bucket_cors_wildcard_origin,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="restricted-cors",
                    region="cn-north-4",
                    cors_allow_origin="https://app.example.com",
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_cors_wildcard_origin().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not allow wildcard CORS" in result[0].status_extended

    def test_bucket_wildcard_cors_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin import (
                obs_bucket_cors_wildcard_origin,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="wildcard-cors",
                    region="cn-north-4",
                    cors_allow_origin="*",
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_cors_wildcard_origin().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "allows wildcard CORS origin" in result[0].status_extended

    def test_bucket_cors_unknown_skipped(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_cors_wildcard_origin.obs_bucket_cors_wildcard_origin import (
                obs_bucket_cors_wildcard_origin,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="unknown-cors",
                    region="cn-north-4",
                    cors_allow_origin=None,
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_cors_wildcard_origin().execute()

            assert len(result) == 0
