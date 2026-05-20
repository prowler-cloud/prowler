from unittest import mock
from unittest.mock import MagicMock, patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class Test_cloudsql_instance_cmek_encryption_enabled:
    def test_no_instances(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                cloudsql_instance_cmek_encryption_enabled,
            )

            cloudsql_client.instances = []
            check = cloudsql_instance_cmek_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_cmek_enabled(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                cloudsql_instance_cmek_encryption_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="db-cmek",
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
                    cmek_key_name="projects/123456789012/locations/europe-west1/keyRings/my-ring/cryptoKeys/my-key",
                )
            ]
            check = cloudsql_instance_cmek_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "db-cmek"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_cmek_not_configured(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                cloudsql_instance_cmek_encryption_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="db-google-managed",
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
                    cmek_key_name=None,
                )
            ]
            check = cloudsql_instance_cmek_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "db-google-managed"
            assert result[0].location == GCP_EU1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_cmek_empty_string(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                cloudsql_instance_cmek_encryption_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="db-empty-key",
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
                    cmek_key_name="",
                )
            ]
            check = cloudsql_instance_cmek_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "db-empty-key"

    def test_unsupported_instance_type_skipped(self):
        cloudsql_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                cloudsql_instance_cmek_encryption_enabled,
            )
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                Instance,
            )

            cloudsql_client.instances = [
                Instance(
                    name="external-primary",
                    version="MYSQL_8_0",
                    ip_addresses=[],
                    region=GCP_EU1_LOCATION,
                    public_ip=False,
                    require_ssl=False,
                    ssl_mode="ENCRYPTED_ONLY",
                    automated_backups=False,
                    authorized_networks=[],
                    flags=[],
                    project_id=GCP_PROJECT_ID,
                    instance_type="ON_PREMISES_INSTANCE",
                    cmek_key_name=None,
                ),
                Instance(
                    name="db-cmek",
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
                    instance_type="CLOUD_SQL_INSTANCE",
                    cmek_key_name="projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
                ),
            ]
            check = cloudsql_instance_cmek_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "db-cmek"
            assert result[0].status == "PASS"

    def test_service_parser_missing_disk_encryption(self):
        """Exercise the real service parser path when diskEncryptionConfiguration is absent."""

        def mock_api_client_without_disk_encryption(*_args, **_kwargs):
            client = MagicMock()
            client.instances().list().execute.return_value = {
                "items": [
                    {
                        "name": "db-no-encryption-config",
                        "databaseVersion": "POSTGRES_14",
                        "region": "us-central1",
                        "ipAddresses": [],
                        "settings": {
                            "ipConfiguration": {"requireSsl": True},
                            "backupConfiguration": {"enabled": True},
                            "databaseFlags": [],
                        },
                    }
                ]
            }
            client.instances().list_next.return_value = None
            return client

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client_without_disk_encryption,
            ),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]),
            ),
        ):
            from prowler.providers.gcp.services.cloudsql.cloudsql_service import (
                CloudSQL,
            )

            cloudsql_client = CloudSQL(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert len(cloudsql_client.instances) == 1
            assert cloudsql_client.instances[0].cmek_key_name is None

            with patch(
                "prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled.cloudsql_client",
                new=cloudsql_client,
            ):
                from prowler.providers.gcp.services.cloudsql.cloudsql_instance_cmek_encryption_enabled.cloudsql_instance_cmek_encryption_enabled import (
                    cloudsql_instance_cmek_encryption_enabled,
                )

                check = cloudsql_instance_cmek_encryption_enabled()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == "db-no-encryption-config"
