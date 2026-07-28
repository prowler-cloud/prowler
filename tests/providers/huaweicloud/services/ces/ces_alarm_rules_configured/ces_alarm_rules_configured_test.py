from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_ces_alarm_rules_configured:
    def test_no_alarms(self):
        ces_client = mock.MagicMock()
        ces_client.alarms = []
        ces_client.region = "la-south-2"
        ces_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured.ces_client",
                new=ces_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured import (
                ces_alarm_rules_configured,
            )

            check = ces_alarm_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No CES alarm rules are configured" in result[0].status_extended

    def test_alarm_enabled(self):
        ces_client = mock.MagicMock()
        ces_client.alarms = [
            mock.MagicMock(
                alarm_id="alarm-001",
                alarm_name="cpu-alarm",
                alarm_enabled=True,
                region="la-south-2",
            )
        ]
        ces_client.region = "la-south-2"
        ces_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured.ces_client",
                new=ces_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured import (
                ces_alarm_rules_configured,
            )

            check = ces_alarm_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "cpu-alarm" in result[0].status_extended

    def test_alarm_disabled(self):
        ces_client = mock.MagicMock()
        ces_client.alarms = [
            mock.MagicMock(
                alarm_id="alarm-002",
                alarm_name="disk-alarm",
                alarm_enabled=False,
                region="la-south-2",
            )
        ]
        ces_client.region = "la-south-2"
        ces_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured.ces_client",
                new=ces_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured import (
                ces_alarm_rules_configured,
            )

            check = ces_alarm_rules_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "disk-alarm" in result[0].status_extended
            assert "disabled" in result[0].status_extended

    def test_mixed_alarms(self):
        ces_client = mock.MagicMock()
        ces_client.alarms = [
            mock.MagicMock(
                alarm_id="alarm-001",
                alarm_name="cpu-alarm",
                alarm_enabled=True,
                region="la-south-2",
            ),
            mock.MagicMock(
                alarm_id="alarm-002",
                alarm_name="disk-alarm",
                alarm_enabled=False,
                region="la-south-2",
            ),
        ]
        ces_client.region = "la-south-2"
        ces_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured.ces_client",
                new=ces_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ces.ces_alarm_rules_configured.ces_alarm_rules_configured import (
                ces_alarm_rules_configured,
            )

            check = ces_alarm_rules_configured()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
