from unittest.mock import patch

from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestMonitoringService:
    def test_service(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert monitoring_client.service == "monitoring"
            assert monitoring_client.project_ids == [GCP_PROJECT_ID]

            assert len(monitoring_client.alert_policies) == 2
            assert monitoring_client.alert_policies[0].name == "alert_policy1"
            assert monitoring_client.alert_policies[0].display_name == "Alert Policy 1"
            assert monitoring_client.alert_policies[0].enabled
            assert monitoring_client.alert_policies[0].filters == [
                'metric.type="compute.googleapis.com/instance/disk/write_bytes_count"'
            ]
            assert monitoring_client.alert_policies[0].project_id == GCP_PROJECT_ID
            assert monitoring_client.alert_policies[1].name == "alert_policy2"
            assert monitoring_client.alert_policies[1].display_name == "Alert Policy 2"
            assert not monitoring_client.alert_policies[1].enabled
            assert monitoring_client.alert_policies[1].filters == [
                'metric.type="compute.googleapis.com/instance/disk/write_bytes_count"'
            ]

    def test_sa_keys_metrics(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            monitoring_client.audit_config = {"max_unused_account_days": 30}
            assert monitoring_client.service == "monitoring"
            assert monitoring_client.project_ids == [GCP_PROJECT_ID]

            assert len(monitoring_client.sa_keys_metrics) == 2
            assert "key1" in monitoring_client.sa_keys_metrics
            assert "key2" in monitoring_client.sa_keys_metrics
            assert "key3" not in monitoring_client.sa_keys_metrics

    def test_sa_api_metrics(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert monitoring_client.service == "monitoring"
            assert monitoring_client.project_ids == [GCP_PROJECT_ID]

            assert len(monitoring_client.sa_api_metrics) == 2
            assert "111222233334444" in monitoring_client.sa_api_metrics
            assert "55566666777888999" in monitoring_client.sa_api_metrics
            assert "0000000000000" not in monitoring_client.sa_api_metrics
