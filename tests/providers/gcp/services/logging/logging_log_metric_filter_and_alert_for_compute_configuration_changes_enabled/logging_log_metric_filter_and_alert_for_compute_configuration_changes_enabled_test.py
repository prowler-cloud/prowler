from unittest.mock import MagicMock, patch

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)


class Test_logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled:
    def test_no_projects(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )

            logging_client.metrics = []
            logging_client.project_ids = []
            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 0

    def test_no_log_metric_filters_no_alerts_one_project(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )

            logging_client.metrics = []
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION
            logging_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="test",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There are no log metric filters or alerts associated for Compute Engine configuration changes in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_no_log_metric_filters_no_alerts_one_project_empty_name(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )

            logging_client.metrics = []
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION
            logging_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="",
                    labels={},
                    lifecycle_state="ACTIVE",
                )
            }

            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There are no log metric filters or alerts associated for Compute Engine configuration changes in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == "GCP Project"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_log_metric_filters_no_alerts(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import Metric

            logging_client.metrics = [
                Metric(
                    name="compute_config_changes",
                    type="logging.googleapis.com/user/compute_config_changes",
                    filter='protoPayload.serviceName="compute.googleapis.com"',
                    project_id=GCP_PROJECT_ID,
                )
            ]
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION

            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log metric filter compute_config_changes found but no alerts associated in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "compute_config_changes"
            assert result[0].resource_name == "compute_config_changes"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_log_metric_filters_with_alerts(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import Metric
            from prowler.providers.gcp.services.monitoring.monitoring_service import (
                AlertPolicy,
            )

            logging_client.metrics = [
                Metric(
                    name="compute_config_changes",
                    type="logging.googleapis.com/user/compute_config_changes",
                    filter='protoPayload.serviceName="compute.googleapis.com"',
                    project_id=GCP_PROJECT_ID,
                )
            ]
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION

            monitoring_client.alert_policies = [
                AlertPolicy(
                    name=f"projects/{GCP_PROJECT_ID}/alertPolicies/12345",
                    display_name="Compute Config Alert",
                    enabled=True,
                    filters=[
                        'metric.type = "logging.googleapis.com/user/compute_config_changes"',
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Log metric filter compute_config_changes found with alert policy Compute Config Alert associated in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "compute_config_changes"
            assert result[0].resource_name == "compute_config_changes"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_multiple_projects_mixed_results(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        project_id_1 = "project-with-monitoring"
        project_id_2 = "project-without-monitoring"

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(
                    project_ids=[project_id_1, project_id_2]
                ),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled import (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import Metric
            from prowler.providers.gcp.services.monitoring.monitoring_service import (
                AlertPolicy,
            )

            logging_client.metrics = [
                Metric(
                    name="compute_config_changes",
                    type="logging.googleapis.com/user/compute_config_changes",
                    filter='protoPayload.serviceName="compute.googleapis.com"',
                    project_id=project_id_1,
                )
            ]
            logging_client.project_ids = [project_id_1, project_id_2]
            logging_client.region = GCP_EU1_LOCATION
            logging_client.projects = {
                project_id_1: GCPProject(
                    id=project_id_1,
                    number="111111111111",
                    name="test-project-1",
                    labels={},
                    lifecycle_state="ACTIVE",
                ),
                project_id_2: GCPProject(
                    id=project_id_2,
                    number="222222222222",
                    name="test-project-2",
                    labels={},
                    lifecycle_state="ACTIVE",
                ),
            }

            monitoring_client.alert_policies = [
                AlertPolicy(
                    name=f"projects/{project_id_1}/alertPolicies/12345",
                    display_name="Compute Config Alert",
                    enabled=True,
                    filters=[
                        'metric.type = "logging.googleapis.com/user/compute_config_changes"',
                    ],
                    project_id=project_id_1,
                )
            ]

            check = (
                logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 2

            # Project 1 should PASS (has metric + alert)
            pass_result = [r for r in result if r.status == "PASS"][0]
            assert pass_result.project_id == project_id_1
            assert "compute_config_changes" in pass_result.status_extended
            assert "Compute Config Alert" in pass_result.status_extended

            # Project 2 should FAIL (no metric)
            fail_result = [r for r in result if r.status == "FAIL"][0]
            assert fail_result.project_id == project_id_2
            assert "no log metric filters" in fail_result.status_extended
