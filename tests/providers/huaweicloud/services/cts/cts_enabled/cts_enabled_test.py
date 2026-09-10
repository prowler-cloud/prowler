from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestCtsEnabled:
    def test_tracker_enabled_passes(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled import (
                cts_enabled,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                status="enabled",
                is_enabled=True,
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "enabled" in result[0].status_extended

    def test_tracker_disabled_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled import (
                cts_enabled,
            )
            from prowler.providers.huaweicloud.services.cts.cts_service import Tracker

            tracker = Tracker(
                id="tracker-1",
                name="system",
                status="disabled",
                is_enabled=False,
                region="la-south-2",
            )
            cts_client.trackers = [tracker]
            cts_client.audited_account = "123456789012"

            check = cts_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended

    def test_no_trackers_fails(self):
        cts_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled.cts_client",
                new=cts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cts.cts_enabled.cts_enabled import (
                cts_enabled,
            )

            cts_client.trackers = []
            cts_client.audited_account = "123456789012"
            cts_client.region = "la-south-2"

            check = cts_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Singleton finding must carry a resource_name so reporting does
            # not emit "has no resource_name".
            assert result[0].resource_name == "123456789012-cts-tracker"
            assert result[0].resource_id == "123456789012-cts-tracker"
