from unittest.mock import patch

from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestCloudSQLService:
    def test_service(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            cloudsql_client = CloudSQL(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert cloudsql_client.service == "sqladmin"
            assert cloudsql_client.project_ids == [GCP_PROJECT_ID]

            assert len(cloudsql_client.instances) == 2

            assert cloudsql_client.instances[0].name == "instance1"
            assert cloudsql_client.instances[0].version == "MYSQL_5_7"
            assert cloudsql_client.instances[0].region == "us-central1"
            assert cloudsql_client.instances[0].ip_addresses == [
                {"type": "PRIMARY", "ipAddress": "66.66.66.66"}
            ]
            assert cloudsql_client.instances[0].public_ip
            assert cloudsql_client.instances[0].require_ssl
            assert cloudsql_client.instances[0].ssl_mode == "ENCRYPTED_ONLY"
            assert cloudsql_client.instances[0].automated_backups
            assert cloudsql_client.instances[0].authorized_networks == [
                {"value": "test"}
            ]
            assert cloudsql_client.instances[0].flags == []
            assert cloudsql_client.instances[0].project_id == GCP_PROJECT_ID

            assert cloudsql_client.instances[1].name == "instance2"
            assert cloudsql_client.instances[1].version == "POSTGRES_9_6"
            assert cloudsql_client.instances[1].region == "us-central1"
            assert cloudsql_client.instances[1].ip_addresses == [
                {"type": "PRIMARY", "ipAddress": "22.22.22.22"}
            ]
            assert cloudsql_client.instances[1].public_ip
            assert not cloudsql_client.instances[1].require_ssl
            assert (
                cloudsql_client.instances[1].ssl_mode
                == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
            )
            assert not cloudsql_client.instances[1].automated_backups
            assert cloudsql_client.instances[1].authorized_networks == [
                {"value": "test"}
            ]
            assert cloudsql_client.instances[1].flags == []
            assert cloudsql_client.instances[1].project_id == GCP_PROJECT_ID

    def test_instances_without_backup_configuration(self):
        """Test that CloudSQL service handles instances without backupConfiguration field"""

        def mock_api_client_without_backup_config(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            client.instances().list().execute.return_value = {
                "items": [
                    {
                        "name": "instance_no_backup_config",
                        "databaseVersion": "MYSQL_8_0",
                        "region": "us-east1",
                        "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.0.0.1"}],
                        "settings": {
                            "ipConfiguration": {
                                "requireSsl": True,
                                "sslMode": "ENCRYPTED_ONLY",
                                "authorizedNetworks": [],
                            },
                            "databaseFlags": [],
                            # backupConfiguration is missing
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
                new=mock_api_client_without_backup_config,
            ),
        ):
            cloudsql_client = CloudSQL(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            # Should handle gracefully with default value
            assert len(cloudsql_client.instances) == 1
            assert cloudsql_client.instances[0].name == "instance_no_backup_config"
            assert (
                cloudsql_client.instances[0].automated_backups is False
            )  # Default value

    def test_instances_with_empty_backup_configuration(self):
        """Test that CloudSQL service handles instances with empty backupConfiguration"""

        def mock_api_client_with_empty_backup_config(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            client.instances().list().execute.return_value = {
                "items": [
                    {
                        "name": "instance_empty_backup_config",
                        "databaseVersion": "POSTGRES_14",
                        "region": "europe-west1",
                        "ipAddresses": [
                            {"type": "PRIMARY", "ipAddress": "34.34.34.34"}
                        ],
                        "settings": {
                            "ipConfiguration": {
                                "requireSsl": False,
                            },
                            "backupConfiguration": {},  # Empty but present
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
                new=mock_api_client_with_empty_backup_config,
            ),
        ):
            cloudsql_client = CloudSQL(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            # Should handle gracefully with default value when 'enabled' key is missing
            assert len(cloudsql_client.instances) == 1
            assert cloudsql_client.instances[0].name == "instance_empty_backup_config"
            assert (
                cloudsql_client.instances[0].automated_backups is False
            )  # Default value

    def test_instances_without_settings_fields(self):
        """Test that CloudSQL service handles instances with minimal settings"""

        def mock_api_client_with_minimal_settings(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            client.instances().list().execute.return_value = {
                "items": [
                    {
                        "name": "instance_minimal",
                        "databaseVersion": "SQLSERVER_2019_STANDARD",
                        "region": "asia-east1",
                        "settings": {},  # Minimal settings object
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
                new=mock_api_client_with_minimal_settings,
            ),
        ):
            cloudsql_client = CloudSQL(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            # Should handle gracefully with all default values
            assert len(cloudsql_client.instances) == 1
            assert cloudsql_client.instances[0].name == "instance_minimal"
            assert cloudsql_client.instances[0].automated_backups is False
            assert cloudsql_client.instances[0].require_ssl is False
            assert (
                cloudsql_client.instances[0].ssl_mode
                == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
            )
            assert cloudsql_client.instances[0].authorized_networks == []
            assert cloudsql_client.instances[0].flags == []
