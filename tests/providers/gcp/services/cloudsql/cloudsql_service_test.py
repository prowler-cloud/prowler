from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.cloudsql.cloudsql_service import CloudSQL
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()
    # Mocking instances
    client.instances().list().execute.return_value = {
        "items": [
            {
                "name": "instance1",
                "databaseVersion": "MYSQL_5_7",
                "region": "us-central1",
                "ipAddresses": [{"type": "PRIMARY", "ipAddress": "66.66.66.66"}],
                "settings": {
                    "ipConfiguration": {
                        "requireSsl": True,
                        "authorizedNetworks": [{"value": "test"}],
                    },
                    "backupConfiguration": {"enabled": True},
                    "databaseFlags": [],
                },
            },
            {
                "name": "instance2",
                "databaseVersion": "POSTGRES_9_6",
                "region": "us-central1",
                "ipAddresses": [{"type": "PRIMARY", "ipAddress": "22.22.22.22"}],
                "settings": {
                    "ipConfiguration": {
                        "requireSsl": False,
                        "authorizedNetworks": [{"value": "test"}],
                    },
                    "backupConfiguration": {"enabled": False},
                    "databaseFlags": [],
                },
            },
        ]
    }
    client.instances().list_next.return_value = None

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_CloudSQL_Service:

    def test__get_service__(self):
        cloudsql_client = CloudSQL(set_mocked_gcp_provider())
        assert cloudsql_client.service == "sqladmin"

    def test__get_project_ids__(self):
        cloudsql_client = CloudSQL(set_mocked_gcp_provider())
        assert cloudsql_client.project_ids.__class__.__name__ == "list"

    def test__get_instances__(self):
        cloudsql_client = CloudSQL(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )

        assert len(cloudsql_client.instances) == 2

        assert cloudsql_client.instances[0].name == "instance1"
        assert cloudsql_client.instances[0].version == "MYSQL_5_7"
        assert cloudsql_client.instances[0].region == "us-central1"
        assert cloudsql_client.instances[0].ip_addresses == [
            {"type": "PRIMARY", "ipAddress": "66.66.66.66"}
        ]
        assert cloudsql_client.instances[0].public_ip
        assert cloudsql_client.instances[0].ssl
        assert cloudsql_client.instances[0].automated_backups
        assert cloudsql_client.instances[0].authorized_networks == [{"value": "test"}]
        assert cloudsql_client.instances[0].flags == []
        assert cloudsql_client.instances[0].project_id == GCP_PROJECT_ID

        assert cloudsql_client.instances[1].name == "instance2"
        assert cloudsql_client.instances[1].version == "POSTGRES_9_6"
        assert cloudsql_client.instances[1].region == "us-central1"
        assert cloudsql_client.instances[1].ip_addresses == [
            {"type": "PRIMARY", "ipAddress": "22.22.22.22"}
        ]
        assert cloudsql_client.instances[1].public_ip
        assert not cloudsql_client.instances[1].ssl
        assert not cloudsql_client.instances[1].automated_backups
        assert cloudsql_client.instances[1].authorized_networks == [{"value": "test"}]
        assert cloudsql_client.instances[1].flags == []
        assert cloudsql_client.instances[1].project_id == GCP_PROJECT_ID
