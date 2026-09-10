from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestWafEnabled:
    def test_waf_running_passes(self):
        waf_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled.waf_client",
                new=waf_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled import (
                waf_enabled,
            )
            from prowler.providers.huaweicloud.services.waf.waf_service import (
                WAFInstance,
            )

            instance = WAFInstance(
                id="waf-1",
                name="my-waf",
                status=1,
                region="la-south-2",
            )
            waf_client.instances = [instance]
            waf_client.audited_account = "123456789012"

            check = waf_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "running" in result[0].status_extended

    def test_waf_not_running_fails(self):
        waf_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled.waf_client",
                new=waf_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled import (
                waf_enabled,
            )
            from prowler.providers.huaweicloud.services.waf.waf_service import (
                WAFInstance,
            )

            instance = WAFInstance(
                id="waf-1",
                name="my-waf",
                status=0,
                region="la-south-2",
            )
            waf_client.instances = [instance]
            waf_client.audited_account = "123456789012"

            check = waf_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not running" in result[0].status_extended

    def test_no_waf_instances_fails(self):
        waf_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled.waf_client",
                new=waf_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.waf.waf_enabled.waf_enabled import (
                waf_enabled,
            )

            waf_client.instances = []
            waf_client.audited_account = "123456789012"
            waf_client.region = "la-south-2"

            check = waf_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended
