from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_bigquery_dataset_public_access:
    def test_bigquery_no_datasets(self):
        bigquery_client = mock.MagicMock
        bigquery_client.datasets = []

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access import (
                bigquery_dataset_public_access,
            )

            check = bigquery_dataset_public_access()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_dataset(self):
        from prowler.providers.gcp.services.bigquery.bigquery_service import Dataset

        dataset = Dataset(
            name="test",
            id="1234567890",
            region="us-central1",
            cmk_encryption=False,
            public=False,
            project_id=GCP_PROJECT_ID,
        )

        bigquery_client = mock.MagicMock
        bigquery_client.project_ids = [GCP_PROJECT_ID]
        bigquery_client.datasets = [dataset]

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access import (
                bigquery_dataset_public_access,
            )

            check = bigquery_dataset_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Dataset {dataset.name} is not publicly accessible."
            )
            assert result[0].resource_id == dataset.id
            assert result[0].resource_name == dataset.name
            assert result[0].project_id == dataset.project_id
            assert result[0].location == dataset.region

    def test_one_non_compliant_dataset(self):
        from prowler.providers.gcp.services.bigquery.bigquery_service import Dataset

        dataset = Dataset(
            name="test",
            id="1234567890",
            region="us-central1",
            cmk_encryption=False,
            public=True,
            project_id=GCP_PROJECT_ID,
        )

        bigquery_client = mock.MagicMock
        bigquery_client.project_ids = [GCP_PROJECT_ID]
        bigquery_client.datasets = [dataset]

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access.bigquery_client",
            new=bigquery_client,
        ):
            from prowler.providers.gcp.services.bigquery.bigquery_dataset_public_access.bigquery_dataset_public_access import (
                bigquery_dataset_public_access,
            )

            check = bigquery_dataset_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Dataset {dataset.name} is publicly accessible."
            )
            assert result[0].resource_id == dataset.id
            assert result[0].resource_name == dataset.name
            assert result[0].project_id == dataset.project_id
            assert result[0].location == dataset.region
