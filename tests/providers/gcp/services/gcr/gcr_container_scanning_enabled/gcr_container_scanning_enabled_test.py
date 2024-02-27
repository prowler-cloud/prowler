from unittest import mock

from prowler.providers.gcp.services.serviceusage.serviceusage_service import Service

GCP_PROJECT_ID = "123456789012"


class Test_gcr_container_scanning_enabled:
    def test_serviceusage_no_active_services(self):
        serviceusage_client = mock.MagicMock
        serviceusage_client.active_services = {}
        serviceusage_client.project_ids = [GCP_PROJECT_ID]
        serviceusage_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gcr.gcr_container_scanning_enabled.gcr_container_scanning_enabled.serviceusage_client",
            new=serviceusage_client,
        ):
            from prowler.providers.gcp.services.gcr.gcr_container_scanning_enabled.gcr_container_scanning_enabled import (
                gcr_container_scanning_enabled,
            )

            check = gcr_container_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GCR Container Analysis is not enabled in project {GCP_PROJECT_ID}"
            )
            assert result[0].resource_id == "containerscanning.googleapis.com"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "GCR Container Analysis"
            assert result[0].location == serviceusage_client.region

    def test_serviceusage_active_cloudasset(self):
        serviceusage_client = mock.MagicMock
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="containerscanning.googleapis.com",
                    title="GCR Container Analysis",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }
        serviceusage_client.project_ids = [GCP_PROJECT_ID]
        serviceusage_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.gcr.gcr_container_scanning_enabled.gcr_container_scanning_enabled.serviceusage_client",
            new=serviceusage_client,
        ):
            from prowler.providers.gcp.services.gcr.gcr_container_scanning_enabled.gcr_container_scanning_enabled import (
                gcr_container_scanning_enabled,
            )

            check = gcr_container_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GCR Container Analysis is enabled in project {GCP_PROJECT_ID}"
            )
            assert result[0].resource_id == "containerscanning.googleapis.com"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "GCR Container Analysis"
            assert result[0].location == serviceusage_client.region
