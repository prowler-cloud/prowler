from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRdsInstanceMultiAz:
    def test_metadata_documents_distinct_availability_zones(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            rds_client.instances = [
                RDSInstance(
                    id="rds-1",
                    name="ha-db",
                    is_multi_az=True,
                    region="la-south-2",
                )
            ]
            rds_client.audited_account = "123456789012"

            metadata = rds_instance_multi_az().execute()[0].check_metadata

            assert (
                "https://support.huaweicloud.com/intl/en-us/api-rds/rds_01_0004.html"
                in metadata.AdditionalURLs
            )
            assert "availability_zone" in metadata.Remediation.Code.Terraform
            assert "ha_replication_mode" in metadata.Remediation.Code.Terraform

    def test_multi_az_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="ha-db",
                is_multi_az=True,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "multiple availability zones" in result[0].status_extended

    def test_single_az_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="single-az-db",
                is_multi_az=False,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "single availability zone" in result[0].status_extended

    def test_no_instances(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_multi_az.rds_instance_multi_az import (
                rds_instance_multi_az,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            check = rds_instance_multi_az()
            result = check.execute()

            assert len(result) == 0
