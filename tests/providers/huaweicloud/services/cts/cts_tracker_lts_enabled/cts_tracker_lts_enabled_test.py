from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestCTSTrackerLtsEnabled:
    def test_no_resources(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled import (
                cts_tracker_lts_enabled,
            )

            cts_client.trackers = []
            cts_client.audited_account = "123456789012"

            result = cts_tracker_lts_enabled().execute()
            assert len(result) == 0

    def test_tracker_lts_enabled_passes(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker
            from prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled import (
                cts_tracker_lts_enabled,
            )

            cts_client.trackers = [
                Tracker(
                    id="tracker-1",
                    name="system",
                    region="cn-north-4",
                    is_lts_enabled=True,
                )
            ]
            cts_client.audited_account = "123456789012"

            result = cts_tracker_lts_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "LTS log transfer enabled" in result[0].status_extended

    def test_tracker_lts_disabled_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker
            from prowler.providers.huaweicloud.services.cts.cts_tracker_lts_enabled.cts_tracker_lts_enabled import (
                cts_tracker_lts_enabled,
            )

            cts_client.trackers = [
                Tracker(
                    id="tracker-2",
                    name="system",
                    region="cn-north-4",
                    is_lts_enabled=False,
                )
            ]
            cts_client.audited_account = "123456789012"

            result = cts_tracker_lts_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have LTS log transfer enabled" in result[0].status_extended
