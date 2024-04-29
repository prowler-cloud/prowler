from unittest.mock import patch

from prowler.providers.gcp.services.serviceusage.serviceusage_service import (
    ServiceUsage,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestServiceUsageService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            serviceusage_client = ServiceUsage(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert serviceusage_client.service == "serviceusage"
            assert serviceusage_client.project_ids == [GCP_PROJECT_ID]

            assert len(serviceusage_client.active_services[GCP_PROJECT_ID]) == 2

            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][0].name
                == "artifacts.googleapis.com"
            )
            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][0].title
                == "artifacts.googleapis.com"
            )
            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][0].project_id
                == GCP_PROJECT_ID
            )
            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][1].name
                == "bigquery.googleapis.com"
            )
            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][1].title
                == "bigquery.googleapis.com"
            )
            assert (
                serviceusage_client.active_services[GCP_PROJECT_ID][1].project_id
                == GCP_PROJECT_ID
            )
