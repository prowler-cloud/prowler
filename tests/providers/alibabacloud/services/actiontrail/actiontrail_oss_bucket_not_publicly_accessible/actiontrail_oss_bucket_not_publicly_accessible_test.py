from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestActionTrailOssBucketNotPubliclyAccessible:
    def test_bucket_missing_marks_manual(self):
        actiontrail_client = mock.MagicMock()
        actiontrail_client.audited_account = "1234567890"
        actiontrail_client.trails = {}
        missing_trail = mock.MagicMock()
        missing_trail.name = "trail-arn"
        missing_trail.oss_bucket_name = "missing-bucket"
        missing_trail.home_region = "cn-hangzhou"
        actiontrail_client.trails["trail-arn"] = missing_trail

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_client",
                new=actiontrail_client,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.oss_client",
                new=mock.MagicMock(buckets={}),
            ),
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible import (
                actiontrail_oss_bucket_not_publicly_accessible,
            )

            check = actiontrail_oss_bucket_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be found" in result[0].status_extended

    def test_public_bucket_fails(self):
        actiontrail_client = mock.MagicMock()
        actiontrail_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_client",
                new=actiontrail_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible import (
                actiontrail_oss_bucket_not_publicly_accessible,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            trail = Trail(
                arn="acs:actiontrail::1234567890:trail/trail1",
                name="trail1",
                home_region="cn-hangzhou",
                trail_region="All",
                status="Enable",
                oss_bucket_name="public-bucket",
                oss_bucket_location="cn-hangzhou",
                sls_project_arn="",
                event_rw="All",
            )
            actiontrail_client.trails = {trail.arn: trail}

            bucket = Bucket(
                arn="acs:oss::1234567890:public-bucket",
                name="public-bucket",
                region="cn-hangzhou",
                acl="public-read",
                policy={},
            )

            oss_client = mock.MagicMock()
            oss_client.buckets = {bucket.arn: bucket}

            with mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.oss_client",
                new=oss_client,
            ):
                check = actiontrail_oss_bucket_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "publicly accessible" in result[0].status_extended

    def test_private_bucket_passes(self):
        actiontrail_client = mock.MagicMock()
        actiontrail_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_client",
                new=actiontrail_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible import (
                actiontrail_oss_bucket_not_publicly_accessible,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )
            from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

            trail = Trail(
                arn="acs:actiontrail::1234567890:trail/trail1",
                name="trail1",
                home_region="cn-hangzhou",
                trail_region="All",
                status="Enable",
                oss_bucket_name="private-bucket",
                oss_bucket_location="cn-hangzhou",
                sls_project_arn="",
                event_rw="All",
            )
            actiontrail_client.trails = {trail.arn: trail}

            bucket = Bucket(
                arn="acs:oss::1234567890:private-bucket",
                name="private-bucket",
                region="cn-hangzhou",
                acl="private",
                policy={},
            )

            oss_client = mock.MagicMock()
            oss_client.buckets = {bucket.arn: bucket}

            with mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_oss_bucket_not_publicly_accessible.actiontrail_oss_bucket_not_publicly_accessible.oss_client",
                new=oss_client,
            ):
                check = actiontrail_oss_bucket_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "not publicly accessible" in result[0].status_extended
