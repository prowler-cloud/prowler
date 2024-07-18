from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_bigquery_table_cmk_encryption:
    def test_bigquery_no_tables(self):
        bigquery_client = mock.MagicMock
        bigquery_client.tables = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption import (
                bigquery_table_cmk_encryption,
            )

            check = bigquery_table_cmk_encryption()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_table(self):
        bigquery_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_service import Table
            from prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption import (
                bigquery_table_cmk_encryption,
            )

            table = Table(
                name="test",
                id="1234567890",
                region="us-central1",
                cmk_encryption=True,
                project_id=GCP_PROJECT_ID,
            )

            bigquery_client.project_ids = [GCP_PROJECT_ID]
            bigquery_client.tables = [table]

            check = bigquery_table_cmk_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Table {table.name} is encrypted with Customer-Managed Keys (CMKs)."
            )
            assert result[0].resource_id == table.id
            assert result[0].resource_name == table.name
            assert result[0].project_id == table.project_id
            assert result[0].location == table.region

    def test_one_non_compliant_table(self):
        bigquery_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_service import Table
            from prowler.providers.gcp.services.bigquery.bigquery_table_cmk_encryption.bigquery_table_cmk_encryption import (
                bigquery_table_cmk_encryption,
            )

            table = Table(
                name="test",
                id="1234567890",
                region="us-central1",
                cmk_encryption=False,
                project_id=GCP_PROJECT_ID,
            )

            bigquery_client.project_ids = [GCP_PROJECT_ID]
            bigquery_client.tables = [table]

            check = bigquery_table_cmk_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Table {table.name} is not encrypted with Customer-Managed Keys (CMKs)."
            )
            assert result[0].resource_id == table.id
            assert result[0].resource_name == table.name
            assert result[0].project_id == table.project_id
            assert result[0].location == table.region
