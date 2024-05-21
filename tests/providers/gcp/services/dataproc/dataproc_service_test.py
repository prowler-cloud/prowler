from unittest.mock import patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestDataprocService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), patch(
            "prowler.providers.gcp.services.dataproc.dataproc_service.compute_client.regions",
            new=["europe-west1-b"],
        ):
            from prowler.providers.gcp.services.dataproc.dataproc_service import (
                Dataproc,
            )

            dataproc_client = Dataproc(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert dataproc_client.service == "dataproc"

            assert dataproc_client.project_ids == [GCP_PROJECT_ID]

            assert len(dataproc_client.clusters) == 2

            assert dataproc_client.clusters[0].name == "cluster1"
            assert dataproc_client.clusters[0].id.__class__.__name__ == "str"
            assert dataproc_client.clusters[0].encryption_config
            assert dataproc_client.clusters[0].project_id == GCP_PROJECT_ID

            assert dataproc_client.clusters[1].name == "cluster2"
            assert dataproc_client.clusters[1].id.__class__.__name__ == "str"
            assert not dataproc_client.clusters[1].encryption_config
            assert dataproc_client.clusters[1].project_id == GCP_PROJECT_ID
