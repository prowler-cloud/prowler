from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestELBListenerHttpsEnabled:
    def test_no_resources(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled import (
                elb_listener_https_enabled,
            )

            elb_client.listeners = []
            elb_client.audited_account = "123456789012"

            result = elb_listener_https_enabled().execute()
            assert len(result) == 0

    def test_https_listener_passes(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled import (
                elb_listener_https_enabled,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import Listener

            elb_client.listeners = [
                Listener(
                    id="lis-1",
                    name="https-listener",
                    protocol="HTTPS",
                    protocol_port=443,
                    region="cn-north-4",
                ),
                Listener(
                    id="lis-tcp",
                    name="tcp-listener",
                    protocol="TCP",
                    protocol_port=8443,
                    region="cn-north-4",
                ),
            ]
            elb_client.audited_account = "123456789012"

            result = elb_listener_https_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "lis-1"
            assert "uses HTTPS protocol" in result[0].status_extended

    def test_http_listener_fails(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_https_enabled.elb_listener_https_enabled import (
                elb_listener_https_enabled,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import Listener

            elb_client.listeners = [
                Listener(
                    id="lis-2",
                    name="http-listener",
                    protocol="HTTP",
                    protocol_port=80,
                    region="cn-north-4",
                )
            ]
            elb_client.audited_account = "123456789012"

            result = elb_listener_https_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses insecure HTTP protocol" in result[0].status_extended
