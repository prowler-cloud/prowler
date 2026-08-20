from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRdsInstanceSslEnabled:
    def test_metadata_uses_rds_ssl_control(self):
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

            metadata = rds_instance_ssl_enabled()

            assert "ssl_enable = true" in metadata.Remediation.Code.Terraform
            assert "MySQL" in metadata.CheckTitle
            assert "MySQL" in metadata.Remediation.Code.Other
            assert "Parameters" not in metadata.Remediation.Code.Other
            assert "rds_08_0032" not in metadata.AdditionalURLs[0]

    def test_ssl_enabled_passes(self):
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

            instance = RDSInstance(
                id="rds-1",
                name="secure-db",
                engine="MySQL",
                enable_ssl=True,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "SSL enabled" in result[0].status_extended

    def test_ssl_disabled_fails(self):
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

            instance = RDSInstance(
                id="rds-1",
                name="insecure-db",
                engine="MySQL",
                enable_ssl=False,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have SSL enabled" in result[0].status_extended

    def test_non_mysql_instance_is_ignored(self):
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
                    name="postgres-db",
                    engine="PostgreSQL",
                    enable_ssl=False,
                    region="la-south-2",
                )
            ]

            check = rds_instance_ssl_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_no_instances(self):
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

            check = rds_instance_ssl_enabled()
            result = check.execute()

            assert len(result) == 0
