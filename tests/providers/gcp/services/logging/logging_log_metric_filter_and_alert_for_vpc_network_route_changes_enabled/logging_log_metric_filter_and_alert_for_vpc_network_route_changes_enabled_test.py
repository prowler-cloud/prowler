from unittest.mock import MagicMock, patch

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)


class Test_logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled:
    def test_no_projects(self):
        logging_client = MagicMock()
        monitoring_client = MagicMock()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
            )

            logging_client.metrics = []
            logging_client.project_ids = []
            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
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
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
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
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There are no log metric filters or alerts associated in project {GCP_PROJECT_ID}."
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
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
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
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There are no log metric filters or alerts associated in project {GCP_PROJECT_ID}."
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
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import Metric

            logging_client.metrics = [
                Metric(
                    name="metric_name",
                    type="custom.googleapis.com/invoice/paid/amount",
                    filter='resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
                    project_id=GCP_PROJECT_ID,
                )
            ]
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION

            monitoring_client.alert_policies = []

            check = (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Log metric filter metric_name found but no alerts associated in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "metric_name"
            assert result[0].resource_name == "metric_name"
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
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import Metric
            from prowler.providers.gcp.services.monitoring.monitoring_service import (
                AlertPolicy,
            )

            logging_client.metrics = [
                Metric(
                    name="metric_name",
                    type="metric_type",
                    filter='resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
                    project_id=GCP_PROJECT_ID,
                )
            ]
            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION

            monitoring_client.alert_policies = [
                AlertPolicy(
                    name=f"projects/{GCP_PROJECT_ID}/alertPolicies/alert_policy",
                    display_name="alert_policy",
                    enabled=True,
                    filters=[
                        'metric.type = "logging.googleapis.com/user/metric_name"',
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Log metric filter metric_name found with alert policy alert_policy associated in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "metric_name"
            assert result[0].resource_name == "metric_name"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_project_centrally_covered_via_org_aggregated_sink(self):
        """A child project with NO local metric, but whose org has an aggregated
        sink (includeChildren=True) routing its logs to a central bucket that has
        a bucket-scoped metric + alert, should PASS (covered centrally)."""
        logging_client = MagicMock()
        monitoring_client = MagicMock()
        org_id = "111222333"
        central_bucket = (
            "projects/central-logging-project/locations/eu/buckets/central-bucket"
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.models import GCPOrganization, GCPProject
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import (
                Metric,
                Sink,
            )
            from prowler.providers.gcp.services.monitoring.monitoring_service import (
                AlertPolicy,
            )

            logging_client.region = GCP_EU1_LOCATION
            logging_client.project_ids = [GCP_PROJECT_ID, "central-logging-project"]
            logging_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="child",
                    labels={},
                    lifecycle_state="ACTIVE",
                    organization=GCPOrganization(
                        id=org_id, name=f"organizations/{org_id}"
                    ),
                )
            }
            logging_client.metrics = [
                Metric(
                    name="central-metric",
                    type="logging.googleapis.com/user/central-metric",
                    filter='resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
                    project_id="central-logging-project",
                    bucket_name=central_bucket,
                )
            ]
            logging_client.sinks = [
                Sink(
                    name="org-aggregated-sink",
                    destination=f"logging.googleapis.com/{central_bucket}",
                    filter="all",
                    project_id=f"organizations/{org_id}",
                    include_children=True,
                )
            ]
            monitoring_client.alert_policies = [
                AlertPolicy(
                    name="projects/central-logging-project/alertPolicies/ap",
                    display_name="central-alert",
                    enabled=True,
                    filters=[
                        'metric.type = "logging.googleapis.com/user/central-metric"'
                    ],
                    project_id="central-logging-project",
                )
            ]

            check = (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()

            assert any(
                r.project_id == GCP_PROJECT_ID
                and r.status == "PASS"
                and "aggregated sink" in r.status_extended
                for r in result
            ), [(r.project_id, r.status, r.status_extended) for r in result]

    def test_aggregated_sink_metric_without_alert_still_fails(self):
        """Guard: an org aggregated sink + a bucket-scoped metric matching the filter
        but with NO alert must NOT credit the child project — it should still FAIL."""
        logging_client = MagicMock()
        monitoring_client = MagicMock()
        org_id = "111222333"
        central_bucket = (
            "projects/central-logging-project/locations/eu/buckets/central-bucket"
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_client",
                new=logging_client,
            ),
            patch(
                "prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.monitoring_client",
                new=monitoring_client,
            ),
        ):
            from prowler.providers.gcp.models import GCPOrganization, GCPProject
            from prowler.providers.gcp.services.logging.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled import (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled,
            )
            from prowler.providers.gcp.services.logging.logging_service import (
                Metric,
                Sink,
            )

            logging_client.region = GCP_EU1_LOCATION
            logging_client.project_ids = [GCP_PROJECT_ID, "central-logging-project"]
            logging_client.projects = {
                GCP_PROJECT_ID: GCPProject(
                    id=GCP_PROJECT_ID,
                    number="123456789012",
                    name="child",
                    labels={},
                    lifecycle_state="ACTIVE",
                    organization=GCPOrganization(
                        id=org_id, name=f"organizations/{org_id}"
                    ),
                )
            }
            logging_client.metrics = [
                Metric(
                    name="central-metric",
                    type="logging.googleapis.com/user/central-metric",
                    filter='resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
                    project_id="central-logging-project",
                    bucket_name=central_bucket,
                )
            ]
            logging_client.sinks = [
                Sink(
                    name="org-aggregated-sink",
                    destination=f"logging.googleapis.com/{central_bucket}",
                    filter="all",
                    project_id=f"organizations/{org_id}",
                    include_children=True,
                )
            ]
            monitoring_client.alert_policies = []  # no alert -> must NOT credit

            check = (
                logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled()
            )
            result = check.execute()

            child = [r for r in result if r.project_id == GCP_PROJECT_ID]
            assert child and all(r.status == "FAIL" for r in child), [
                (r.project_id, r.status) for r in result
            ]
