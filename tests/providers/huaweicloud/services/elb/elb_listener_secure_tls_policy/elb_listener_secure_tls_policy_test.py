from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestELBListenerSecureTlsPolicy:
    def test_no_resources(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy import (
                elb_listener_secure_tls_policy,
            )

            elb_client.listeners = []
            elb_client.audited_account = "123456789012"

            result = elb_listener_secure_tls_policy().execute()
            assert len(result) == 0

    def test_secure_tls_1_2_policy_passes(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy import (
                elb_listener_secure_tls_policy,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import Listener

            elb_client.listeners = [
                Listener(
                    id="lis-1",
                    name="tls12-listener",
                    protocol="HTTPS",
                    protocol_port=443,
                    tls_ciphers_policy="tls-1-2-strict",
                    region="cn-north-4",
                )
            ]
            elb_client.audited_account = "123456789012"

            result = elb_listener_secure_tls_policy().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "uses secure TLS policy" in result[0].status_extended

    def test_legacy_tls_1_0_policy_fails(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_listener_secure_tls_policy.elb_listener_secure_tls_policy import (
                elb_listener_secure_tls_policy,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import Listener

            elb_client.listeners = [
                Listener(
                    id="lis-2",
                    name="legacy-tls-listener",
                    protocol="TERMINATED_HTTPS",
                    protocol_port=443,
                    tls_ciphers_policy="tls-1-0",
                    region="cn-north-4",
                )
            ]
            elb_client.audited_account = "123456789012"

            result = elb_listener_secure_tls_policy().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses insecure TLS policy" in result[0].status_extended
