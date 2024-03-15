from unittest import mock

from prowler.providers.gcp.services.serviceusage.serviceusage_service import Service
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_artifacts_container_analysis_enabled:
    def test_serviceusage_no_active_services(self):
        serviceusage_client = mock.MagicMock
        serviceusage_client.active_services = {}
        serviceusage_client.project_ids = [GCP_PROJECT_ID]
        serviceusage_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.artifacts.artifacts_container_analysis_enabled.artifacts_container_analysis_enabled.serviceusage_client",
            new=serviceusage_client,
        ):
            from prowler.providers.gcp.services.artifacts.artifacts_container_analysis_enabled.artifacts_container_analysis_enabled import (
                artifacts_container_analysis_enabled,
            )

            check = artifacts_container_analysis_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AR Container Analysis is not enabled in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "containeranalysis.googleapis.com"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "AR Container Analysis"
            assert result[0].location == serviceusage_client.region

    def test_serviceusage_active_cloudasset(self):
        serviceusage_client = mock.MagicMock
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="containeranalysis.googleapis.com",
                    title="AR Container Analysis",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }
        serviceusage_client.project_ids = [GCP_PROJECT_ID]
        serviceusage_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.artifacts.artifacts_container_analysis_enabled.artifacts_container_analysis_enabled.serviceusage_client",
            new=serviceusage_client,
        ):
            from prowler.providers.gcp.services.artifacts.artifacts_container_analysis_enabled.artifacts_container_analysis_enabled import (
                artifacts_container_analysis_enabled,
            )

            check = artifacts_container_analysis_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AR Container Analysis is enabled in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "containeranalysis.googleapis.com"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "AR Container Analysis"
            assert result[0].location == serviceusage_client.region
