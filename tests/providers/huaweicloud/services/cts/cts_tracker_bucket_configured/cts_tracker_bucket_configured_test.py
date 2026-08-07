from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestCtsTrackerBucketConfigured:
    def test_tracker_with_bucket_passes(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured import (
                cts_tracker_bucket_configured,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                is_enabled=True,
                bucket_name="cts-audit-bucket",
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_tracker_bucket_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "cts-audit-bucket" in result[0].status_extended

    def test_tracker_without_bucket_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured import (
                cts_tracker_bucket_configured,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                is_enabled=True,
                bucket_name="",
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_tracker_bucket_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have an OBS bucket" in result[0].status_extended

    def test_no_trackers_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_bucket_configured.cts_tracker_bucket_configured import (
                cts_tracker_bucket_configured,
            )

            cts_client.trackers = []
            cts_client.audited_account = "123456789012"
            cts_client.region = "la-south-2"

            check = cts_tracker_bucket_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
