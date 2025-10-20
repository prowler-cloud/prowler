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

    def test_alert_policies_with_different_condition_types(self):
        """Test that monitoring service handles different alert policy condition types"""

        def mock_api_client_with_mixed_conditions(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            # Mock alert policies with different condition types
            client.projects().alertPolicies().list().execute.return_value = {
                "alertPolicies": [
                    {
                        "name": "policy_with_threshold",
                        "displayName": "Threshold Policy",
                        "conditions": [
                            {
                                "conditionThreshold": {
                                    "filter": 'metric.type="compute.googleapis.com/instance/cpu/utilization"',
                                    "comparison": "COMPARISON_GT",
                                    "thresholdValue": 0.8,
                                }
                            }
                        ],
                        "enabled": True,
                    },
                    {
                        "name": "policy_with_absent",
                        "displayName": "Absent Policy",
                        "conditions": [
                            {
                                "conditionAbsent": {
                                    "filter": 'metric.type="compute.googleapis.com/instance/uptime"',
                                    "duration": "300s",
                                }
                            }
                        ],
                        "enabled": True,
                    },
                    {
                        "name": "policy_with_log",
                        "displayName": "Log Match Policy",
                        "conditions": [
                            {
                                "conditionMatchedLog": {
                                    "filter": 'severity="ERROR"',
                                }
                            }
                        ],
                        "enabled": True,
                    },
                    {
                        "name": "policy_with_mql",
                        "displayName": "MQL Policy",
                        "conditions": [
                            {
                                "conditionMonitoringQueryLanguage": {
                                    "query": 'fetch gce_instance | metric "compute.googleapis.com/instance/cpu/utilization"',
                                    "duration": "60s",
                                }
                            }
                        ],
                        "enabled": True,
                    },
                ]
            }
            client.projects().alertPolicies().list_next.return_value = None
            client.projects().timeSeries().list().execute.return_value = {
                "timeSeries": []
            }

            return client

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client_with_mixed_conditions,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(monitoring_client.alert_policies) == 4

            # Verify threshold condition
            threshold_policy = monitoring_client.alert_policies[0]
            assert threshold_policy.name == "policy_with_threshold"
            assert len(threshold_policy.filters) == 1
            assert (
                'metric.type="compute.googleapis.com/instance/cpu/utilization"'
                in threshold_policy.filters[0]
            )

            # Verify absent condition
            absent_policy = monitoring_client.alert_policies[1]
            assert absent_policy.name == "policy_with_absent"
            assert len(absent_policy.filters) == 1
            assert (
                'metric.type="compute.googleapis.com/instance/uptime"'
                in absent_policy.filters[0]
            )

            # Verify log condition
            log_policy = monitoring_client.alert_policies[2]
            assert log_policy.name == "policy_with_log"
            assert len(log_policy.filters) == 1
            assert 'severity="ERROR"' in log_policy.filters[0]

            # Verify MQL condition
            mql_policy = monitoring_client.alert_policies[3]
            assert mql_policy.name == "policy_with_mql"
            assert len(mql_policy.filters) == 1
            assert "fetch gce_instance" in mql_policy.filters[0]

    def test_alert_policies_with_missing_conditions(self):
        """Test that monitoring service handles alert policies with missing conditions field"""

        def mock_api_client_with_missing_conditions(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            client.projects().alertPolicies().list().execute.return_value = {
                "alertPolicies": [
                    {
                        "name": "policy_without_conditions",
                        "displayName": "Policy Without Conditions",
                        "enabled": True,
                    }
                ]
            }
            client.projects().alertPolicies().list_next.return_value = None
            client.projects().timeSeries().list().execute.return_value = {
                "timeSeries": []
            }

            return client

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client_with_missing_conditions,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            # Should handle gracefully and create policy with empty filters
            assert len(monitoring_client.alert_policies) == 1
            assert (
                monitoring_client.alert_policies[0].name == "policy_without_conditions"
            )
            assert monitoring_client.alert_policies[0].filters == []

    def test_alert_policies_with_empty_filter_values(self):
        """Test that monitoring service skips conditions with empty filter values"""

        def mock_api_client_with_empty_filters(*args, **kwargs):
            from unittest.mock import MagicMock

            client = MagicMock()

            client.projects().alertPolicies().list().execute.return_value = {
                "alertPolicies": [
                    {
                        "name": "policy_with_empty_filter",
                        "displayName": "Policy With Empty Filter",
                        "conditions": [
                            {
                                "conditionThreshold": {
                                    "filter": "",  # Empty filter
                                    "comparison": "COMPARISON_GT",
                                    "thresholdValue": 1000,
                                }
                            }
                        ],
                        "enabled": True,
                    }
                ]
            }
            client.projects().alertPolicies().list_next.return_value = None
            client.projects().timeSeries().list().execute.return_value = {
                "timeSeries": []
            }

            return client

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client_with_empty_filters,
            ),
        ):
            monitoring_client = Monitoring(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            # Should skip empty filters
            assert len(monitoring_client.alert_policies) == 1
            assert monitoring_client.alert_policies[0].filters == []
