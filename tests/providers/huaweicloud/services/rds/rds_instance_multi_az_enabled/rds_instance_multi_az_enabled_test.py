from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRDSInstanceMultiAzEnabled:
    def test_no_resources(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled import (
                rds_instance_multi_az_enabled,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            result = rds_instance_multi_az_enabled().execute()
            assert len(result) == 0

    def test_rds_ha_instance_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled import (
                rds_instance_multi_az_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            rds_client.instances = [
                RDSInstance(
                    id="rds-1",
                    name="ha-db",
                    region="cn-north-4",
                    instance_type="Ha",
                    ha_mode="ha",
                )
            ]
            rds_client.audited_account = "123456789012"

            result = rds_instance_multi_az_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "high availability" in result[0].status_extended

    def test_rds_single_instance_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az_enabled.rds_instance_multi_az_enabled import (
                rds_instance_multi_az_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            rds_client.instances = [
                RDSInstance(
                    id="rds-2",
                    name="single-db",
                    region="cn-north-4",
                    instance_type="Single",
                    ha_mode="",
                )
            ]
            rds_client.audited_account = "123456789012"

            result = rds_instance_multi_az_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have high availability" in result[0].status_extended
