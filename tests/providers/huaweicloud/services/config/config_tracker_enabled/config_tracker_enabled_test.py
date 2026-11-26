from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestConfigTrackerEnabled:
    def test_tracker_enabled_passes(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_tracker_enabled.config_tracker_enabled.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_service import (
                TrackerConfig,
            )
            from prowler.providers.huaweicloud.services.config.config_tracker_enabled.config_tracker_enabled import (
                config_tracker_enabled,
            )

            config_client.tracker_config = TrackerConfig(
                agency_name="rms_agency",
                tracker_enabled=True,
            )
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_tracker_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "tracker is enabled" in result[0].status_extended

    def test_tracker_not_enabled_fails(self):
        config_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.config.config_tracker_enabled.config_tracker_enabled.config_client",
                new=config_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.config.config_service import (
                TrackerConfig,
            )
            from prowler.providers.huaweicloud.services.config.config_tracker_enabled.config_tracker_enabled import (
                config_tracker_enabled,
            )

            config_client.tracker_config = TrackerConfig(
                agency_name="",
                tracker_enabled=False,
            )
            config_client.audited_account = "123456789012"
            config_client.region = "la-south-2"

            check = config_tracker_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended
