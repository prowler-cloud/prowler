from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestCtsTrackerTypeSystem:
    def test_system_tracker_enabled_passes(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system import (
                cts_tracker_type_system,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                tracker_type="system",
                is_enabled=True,
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_tracker_type_system()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "system" in result[0].status_extended

    def test_no_system_tracker_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system import (
                cts_tracker_type_system,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="data-tracker",
                tracker_type="data",
                is_enabled=True,
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_tracker_type_system()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No enabled system-type" in result[0].status_extended

    def test_system_tracker_disabled_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system import (
                cts_tracker_type_system,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                tracker_type="system",
                is_enabled=False,
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_tracker_type_system()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No enabled system-type" in result[0].status_extended

    def test_no_trackers_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_tracker_type_system.cts_tracker_type_system import (
                cts_tracker_type_system,
            )

            cts_client.trackers = []
            cts_client.audited_account = "123456789012"
            cts_client.region = "la-south-2"

            check = cts_tracker_type_system()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No CTS tracker found" in result[0].status_extended
