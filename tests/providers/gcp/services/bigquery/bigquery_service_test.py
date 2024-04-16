from unittest.mock import MagicMock, patch
from uuid import uuid4

from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()
    # Mocking datasets
    dataset1_id = str(uuid4())
    dataset2_id = str(uuid4())

    client.datasets().list().execute.return_value = {
        "datasets": [
            {
                "datasetReference": {"datasetId": "dataset1"},
                "id": dataset1_id,
                "location": "US",
            },
            {
                "datasetReference": {"datasetId": "dataset2"},
                "id": dataset2_id,
                "location": "EU",
            },
        ]
    }
    # When getting the dataset info, the first dataset is public and the second is not
    client.datasets().get().execute.side_effect = [
        {
            "access": "allAuthenticatedUsers",
            "defaultEncryptionConfiguration": True,
        },
        {
            "access": "nobody",
            "defaultEncryptionConfiguration": False,
        },
    ]
    client.datasets().list_next.return_value = None

    # Mocking tables for firts dataset, the second dataset has no tables
    table1_id = str(uuid4())
    table2_id = str(uuid4())

    client.tables().list().execute.side_effect = [
        {
            "tables": [
                {
                    "tableReference": {"tableId": "table1"},
                    "id": table1_id,
                },
                {
                    "tableReference": {"tableId": "table2"},
                    "id": table2_id,
                },
            ]
        },
        {"tables": []},
    ]
    # When getting the table info, the first table is encrypted and the second is not
    client.tables().get().execute.side_effect = [
        {
            "encryptionConfiguration": True,
        },
        {
            "encryptionConfiguration": False,
        },
    ]
    client.tables().list_next.return_value = None

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_BigQuery_Service:
    def test__get_service__(self):
        api_keys_client = BigQuery(set_mocked_gcp_provider())
        assert api_keys_client.service == "bigquery"

    def test__get_project_ids__(self):
        api_keys_client = BigQuery(set_mocked_gcp_provider())
        assert api_keys_client.project_ids.__class__.__name__ == "list"

    def test__get_datasets__(self):
        api_keys_client = BigQuery(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )

        assert len(api_keys_client.datasets) == 2

        assert api_keys_client.datasets[0].name == "dataset1"
        assert api_keys_client.datasets[0].id.__class__.__name__ == "str"
        assert api_keys_client.datasets[0].region == "US"
        assert api_keys_client.datasets[0].cmk_encryption
        assert api_keys_client.datasets[0].public
        assert api_keys_client.datasets[0].project_id == GCP_PROJECT_ID

        assert api_keys_client.datasets[1].name == "dataset2"
        assert api_keys_client.datasets[1].id.__class__.__name__ == "str"
        assert api_keys_client.datasets[1].region == "EU"
        assert not api_keys_client.datasets[1].cmk_encryption
        assert not api_keys_client.datasets[1].public
        assert api_keys_client.datasets[1].project_id == GCP_PROJECT_ID

    def test__get_tables__(self):
        api_keys_client = BigQuery(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )

        assert len(api_keys_client.tables) == 2

        assert api_keys_client.tables[0].name == "table1"
        assert api_keys_client.tables[0].id.__class__.__name__ == "str"
        assert api_keys_client.tables[0].region == "US"
        assert api_keys_client.tables[0].cmk_encryption
        assert api_keys_client.tables[0].project_id == GCP_PROJECT_ID

        assert api_keys_client.tables[1].name == "table2"
        assert api_keys_client.tables[1].id.__class__.__name__ == "str"
        assert api_keys_client.tables[1].region == "US"
        assert not api_keys_client.tables[1].cmk_encryption
        assert api_keys_client.tables[1].project_id == GCP_PROJECT_ID
