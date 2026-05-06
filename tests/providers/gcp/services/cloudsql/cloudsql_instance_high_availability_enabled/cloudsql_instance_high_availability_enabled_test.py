from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)


class Test_cloudsql_instance_high_availability_enabled:
    def test_no_instances(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled import (
                cloudsql_instance_high_availability_enabled,
            )
            cloudsql_client.instances = []
            check = cloudsql_instance_high_availability_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_ha_enabled(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled import (
                cloudsql_instance_high_availability_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import Instance
            cloudsql_client.instances = [
                Instance(
                    name="db-ha",
                    version="POSTGRES_15",
                    ip_addresses=[],
                    region=GCP_EU1_LOCATION,
                    public_ip=False,
                    require_ssl=False,
                    ssl_mode="ENCRYPTED_ONLY",
                    automated_backups=True,
                    authorized_networks=[],
                    flags=[],
                    project_id=GCP_PROJECT_ID,
                    high_availability=True,
                )
            ]
            check = cloudsql_instance_high_availability_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "db-ha"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_ha_disabled(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_high_availability_enabled.cloudsql_instance_high_availability_enabled import (
                cloudsql_instance_high_availability_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import Instance
            cloudsql_client.instances = [
                Instance(
                    name="db-zonal",
                    version="POSTGRES_15",
                    ip_addresses=[],
                    region=GCP_EU1_LOCATION,
                    public_ip=False,
                    require_ssl=False,
                    ssl_mode="ENCRYPTED_ONLY",
                    automated_backups=True,
                    authorized_networks=[],
                    flags=[],
                    project_id=GCP_PROJECT_ID,
                    high_availability=False,
                )
            ]
            check = cloudsql_instance_high_availability_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "db-zonal"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
