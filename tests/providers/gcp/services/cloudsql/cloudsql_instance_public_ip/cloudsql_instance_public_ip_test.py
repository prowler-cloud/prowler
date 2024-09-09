from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)


class Test_cloudsql_instance_public_ip:
    def test_no_cloudsql_instances(self):
        cloudsql_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip.cloudsql_client",
            new=cloudsql_client,
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip import (
                cloudsql_instance_public_ip,
            )

            cloudsql_client.instances = []

            check = cloudsql_instance_public_ip()
            result = check.execute()
            assert len(result) == 0

    def test_cloudsql_instance_no_public_ip(self):
        cloudsql_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip.cloudsql_client",
            new=cloudsql_client,
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip import (
                cloudsql_instance_public_ip,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="instance1",
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
                )
            ]

            check = cloudsql_instance_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Database Instance instance1 does not have a public IP."
            )
            assert result[0].resource_id == "instance1"
            assert result[0].resource_name == "instance1"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_cloudsql_instance_public_ip(self):
        cloudsql_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip.cloudsql_client",
            new=cloudsql_client,
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_public_ip.cloudsql_instance_public_ip import (
                cloudsql_instance_public_ip,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="instance1",
                    version="POSTGRES_15",
                    ip_addresses=[],
                    region=GCP_EU1_LOCATION,
                    public_ip=True,
                    require_ssl=False,
                    ssl_mode="ENCRYPTED_ONLY",
                    automated_backups=True,
                    authorized_networks=[],
                    flags=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = cloudsql_instance_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Database Instance instance1 has a public IP."
            )
            assert result[0].resource_id == "instance1"
            assert result[0].resource_name == "instance1"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
