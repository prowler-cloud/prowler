from unittest.mock import patch

from prowler.providers.gcp.services.bigquery.bigquery_service import BigQuery
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestBigQueryService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            bigquery_client = BigQuery(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert bigquery_client.service == "bigquery"
            assert bigquery_client.project_ids == [GCP_PROJECT_ID]

            assert len(bigquery_client.datasets) == 2

            assert bigquery_client.datasets[0].name == "unique_dataset1_name"
            assert bigquery_client.datasets[0].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[0].region == "US"
            assert bigquery_client.datasets[0].cmk_encryption
            assert bigquery_client.datasets[0].public
            assert bigquery_client.datasets[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.datasets[1].name == "unique_dataset2_name"
            assert bigquery_client.datasets[1].id.__class__.__name__ == "str"
            assert bigquery_client.datasets[1].region == "EU"
            assert not bigquery_client.datasets[1].cmk_encryption
            assert not bigquery_client.datasets[1].public
            assert bigquery_client.datasets[1].project_id == GCP_PROJECT_ID

            assert len(bigquery_client.tables) == 2

            assert bigquery_client.tables[0].name == "unique_table1_name"
            assert bigquery_client.tables[0].id.__class__.__name__ == "str"
            assert bigquery_client.tables[0].region == "US"
            assert bigquery_client.tables[0].cmk_encryption
            assert bigquery_client.tables[0].project_id == GCP_PROJECT_ID

            assert bigquery_client.tables[1].name == "unique_table2_name"
            assert bigquery_client.tables[1].id.__class__.__name__ == "str"
            assert bigquery_client.tables[1].region == "US"
            assert not bigquery_client.tables[1].cmk_encryption
            assert bigquery_client.tables[1].project_id == GCP_PROJECT_ID
