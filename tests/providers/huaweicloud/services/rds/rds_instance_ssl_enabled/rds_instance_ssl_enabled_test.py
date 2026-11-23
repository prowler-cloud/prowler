from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRDSInstanceSslEnabled:
    def test_no_resources(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled import (
                rds_instance_ssl_enabled,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            result = rds_instance_ssl_enabled().execute()
            assert len(result) == 0

    def test_rds_ssl_enabled_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled import (
                rds_instance_ssl_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            rds_client.instances = [
                RDSInstance(
                    id="rds-1",
                    name="ssl-db",
                    region="cn-north-4",
                    enable_ssl=True,
                )
            ]
            rds_client.audited_account = "123456789012"

            result = rds_instance_ssl_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has SSL encryption enabled" in result[0].status_extended

    def test_rds_ssl_disabled_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_ssl_enabled.rds_instance_ssl_enabled import (
                rds_instance_ssl_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            rds_client.instances = [
                RDSInstance(
                    id="rds-2",
                    name="plain-db",
                    region="cn-north-4",
                    enable_ssl=False,
                )
            ]
            rds_client.audited_account = "123456789012"

            result = rds_instance_ssl_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have SSL encryption enabled" in result[0].status_extended
