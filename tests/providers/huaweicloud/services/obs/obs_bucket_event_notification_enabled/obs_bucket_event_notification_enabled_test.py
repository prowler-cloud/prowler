from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestObsBucketEventNotificationEnabled:
    def test_no_resources(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled import (
                obs_bucket_event_notification_enabled,
            )

            obs_client.buckets = []
            obs_client.audited_account = "123456789012"

            result = obs_bucket_event_notification_enabled().execute()
            assert len(result) == 0

    def test_bucket_notification_enabled_passes(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled import (
                obs_bucket_event_notification_enabled,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="notified-bucket",
                    region="cn-north-4",
                    event_notification_enabled=True,
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_event_notification_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "event notifications enabled" in result[0].status_extended

    def test_bucket_notification_disabled_fails(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled import (
                obs_bucket_event_notification_enabled,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="unnotified-bucket",
                    region="cn-north-4",
                    event_notification_enabled=False,
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_event_notification_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "does not have event notifications enabled" in result[0].status_extended
            )

    def test_bucket_notification_unknown_skipped(self):
        obs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled.obs_client",
                new=obs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.obs.obs_bucket_event_notification_enabled.obs_bucket_event_notification_enabled import (
                obs_bucket_event_notification_enabled,
            )
            from prowler.providers.huaweicloud.services.obs.obs_service import Bucket

            obs_client.buckets = [
                Bucket(
                    name="unknown-bucket",
                    region="cn-north-4",
                    event_notification_enabled=None,
                )
            ]
            obs_client.audited_account = "123456789012"

            result = obs_bucket_event_notification_enabled().execute()

            assert len(result) == 0
