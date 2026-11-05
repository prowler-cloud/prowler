import json
from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRdsInstanceHighAvailability:
    def test_ha_enabled_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability import (
                rds_instance_high_availability,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="ha-db",
                is_ha=True,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_high_availability()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "high availability configured" in result[0].status_extended

    def test_ha_disabled_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability import (
                rds_instance_high_availability,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="single-db",
                is_ha=False,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_instance_high_availability()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have high availability" in result[0].status_extended

    def test_no_instances(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_instance_high_availability.rds_instance_high_availability import (
                rds_instance_high_availability,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            check = rds_instance_high_availability()
            result = check.execute()

            assert len(result) == 0

            metadata = json.loads(check.metadata())
            assert (
                "https://support.huaweicloud.com/intl/en-us/api-rds/rds_01_0004.html"
                in metadata["AdditionalURLs"]
            )
            assert "ha_replication_mode" in metadata["Remediation"]["Code"]["Terraform"]
            assert (
                "Create Standby Instance"
                not in metadata["Remediation"]["Code"]["Other"]
            )
