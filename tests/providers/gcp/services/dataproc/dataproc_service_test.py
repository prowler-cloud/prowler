from unittest.mock import MagicMock, patch
from uuid import uuid4

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()

    # Mocking clusters
    cluster1_id = str(uuid4())
    cluster2_id = str(uuid4())

    client.projects().regions().clusters().list().execute.return_value = {
        "clusters": [
            {
                "clusterName": "cluster1",
                "clusterUuid": cluster1_id,
                "config": {
                    "encryptionConfig": {
                        "gcePdKmsKeyName": "projects/123/locations/456/keyRings/789/cryptoKeys/123"
                    }
                },
            },
            {
                "clusterName": "cluster2",
                "clusterUuid": cluster2_id,
                "config": {"encryptionConfig": {}},
            },
        ]
    }
    client.projects().regions().clusters().list_next().execute.return_value = None

    return client


def mocked_compute_client(_, __):
    compute_client = MagicMock()
    compute_client.regions = ["region1"]

    return compute_client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
@patch(
    "prowler.providers.gcp.services.compute.compute_service.Compute.__new__",
    new=mocked_compute_client,
)
class Test_Dataproc_Service:
    def test__get_service__(self):
        from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

        dataproc_client = Dataproc(set_mocked_gcp_provider())
        assert dataproc_client.service == "dataproc"

    def test__get_project_ids__(self):
        from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

        dataproc_client = Dataproc(set_mocked_gcp_provider())
        assert dataproc_client.project_ids.__class__.__name__ == "list"

    def test__get_clusters__(self):
        from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

        dataproc_client = Dataproc(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )
        assert len(dataproc_client.clusters) == 2

        assert dataproc_client.clusters[0].name == "cluster1"
        assert dataproc_client.clusters[0].id.__class__.__name__ == "str"
        assert dataproc_client.clusters[0].encryption_config
        assert dataproc_client.clusters[0].project_id == GCP_PROJECT_ID

        assert dataproc_client.clusters[1].name == "cluster2"
        assert dataproc_client.clusters[1].id.__class__.__name__ == "str"
        assert not dataproc_client.clusters[1].encryption_config
        assert dataproc_client.clusters[1].project_id == GCP_PROJECT_ID
