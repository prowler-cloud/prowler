from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestWafInstanceConfigured:
    def test_waf_instance_configured_passes(self):
        waf_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.waf.waf_instance_configured.waf_instance_configured.waf_client",
                new=waf_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.waf.waf_instance_configured.waf_instance_configured import (
                waf_instance_configured,
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

            check = waf_instance_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "configured" in result[0].status_extended

    def test_no_waf_instances_fails(self):
        waf_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.waf.waf_instance_configured.waf_instance_configured.waf_client",
                new=waf_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.waf.waf_instance_configured.waf_instance_configured import (
                waf_instance_configured,
            )

            waf_client.instances = []
            waf_client.audited_account = "123456789012"
            waf_client.region = "la-south-2"

            check = waf_instance_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No WAF instances" in result[0].status_extended
