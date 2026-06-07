from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.logging.logging_service import Logging
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestLoggingService:
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
            logging_client = Logging(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert logging_client.service == "logging"
            assert logging_client.project_ids == [GCP_PROJECT_ID]

            assert len(logging_client.sinks) == 2

            assert logging_client.sinks[0].name == "sink1"
            assert (
                logging_client.sinks[0].destination
                == "storage.googleapis.com/example-bucket"
            )
            assert logging_client.sinks[0].filter == "all"
            assert logging_client.sinks[0].project_id == GCP_PROJECT_ID
            assert logging_client.sinks[1].name == "sink2"
            assert (
                logging_client.sinks[1].destination
                == f"bigquery.googleapis.com/projects/{GCP_PROJECT_ID}/datasets/example_dataset"
            )
            assert logging_client.sinks[1].filter == "all"
            assert logging_client.sinks[1].project_id == GCP_PROJECT_ID

            assert len(logging_client.metrics) == 2

            assert logging_client.metrics[0].name == "metric1"
            assert (
                logging_client.metrics[0].type
                == "custom.googleapis.com/invoice/paid/amount"
            )
            assert (
                logging_client.metrics[0].filter
                == "resource.type=gae_app AND severity>=ERROR"
            )
            assert logging_client.metrics[0].project_id == GCP_PROJECT_ID
            assert logging_client.metrics[1].name == "metric2"
            assert (
                logging_client.metrics[1].type
                == "external.googleapis.com/prometheus/up"
            )
            assert (
                logging_client.metrics[1].filter
                == "resource.type=gae_app AND severity>=ERROR"
            )
            assert logging_client.metrics[1].project_id == GCP_PROJECT_ID

    def test_org_sinks_fetched_when_project_has_organization(self):
        """_get_org_sinks() appends org-level sinks when projects have an org."""
        from prowler.providers.gcp.models import GCPOrganization, GCPProject

        org_id = "999888777"
        provider = set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        provider.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test",
                labels={},
                lifecycle_state="ACTIVE",
                organization=GCPOrganization(id=org_id, name=f"organizations/{org_id}"),
            )
        }

        mock_client = MagicMock()
        mock_client.sinks().list().execute.return_value = {
            "sinks": [
                {
                    "name": "org-sink",
                    "destination": "storage.googleapis.com/org-bucket",
                    "filter": "all",
                    "includeChildren": True,
                }
            ]
        }
        mock_client.sinks().list_next.return_value = None
        mock_client.projects().metrics().list().execute.return_value = {"metrics": []}
        mock_client.projects().metrics().list_next.return_value = None

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=mock_client,
            ),
        ):
            logging_svc = Logging(provider)

        org_sinks = [
            s for s in logging_svc.sinks if s.project_id == f"organizations/{org_id}"
        ]
        assert len(org_sinks) == 1
        assert org_sinks[0].name == "org-sink"
        assert org_sinks[0].include_children is True
        assert org_sinks[0].filter == "all"

    def test_org_sinks_skipped_when_no_organization(self):
        """_get_org_sinks() adds nothing when projects have no organization."""
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
            logging_svc = Logging(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

        org_sinks = [
            s for s in logging_svc.sinks if s.project_id.startswith("organizations/")
        ]
        assert org_sinks == []

    def test_get_metrics_populates_bucket_name(self):
        """_get_metrics() captures a metric's bucketName (for aggregated-sink crediting)."""
        bucket = "projects/central-logging-project/locations/eu/buckets/central-bucket"
        mock_client = MagicMock()
        mock_client.sinks().list().execute.return_value = {"sinks": []}
        mock_client.sinks().list_next.return_value = None
        mock_client.projects().metrics().list().execute.return_value = {
            "metrics": [
                {
                    "name": "central-metric",
                    "metricDescriptor": {
                        "type": "logging.googleapis.com/user/central-metric"
                    },
                    "filter": "severity>=ERROR",
                    "bucketName": bucket,
                }
            ]
        }
        mock_client.projects().metrics().list_next.return_value = None

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=mock_client,
            ),
        ):
            logging_svc = Logging(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

        metrics = [m for m in logging_svc.metrics if m.name == "central-metric"]
        assert len(metrics) == 1
        assert metrics[0].bucket_name == bucket


class TestGetProjectsCoveredByAggregatedMetric:
    """Unit tests for the aggregated-sink crediting helper: one positive case and the
    guards that must NOT credit a project (so the metric-filter checks never false-pass).
    """

    FILTER = 'protoPayload.methodName="SetIamPolicy"'
    ORG = "111222333"
    BUCKET = "projects/central-logging-project/locations/eu/buckets/central-bucket"

    def _clients(
        self,
        *,
        include_children=True,
        bucket_name=None,
        sink_destination=None,
        with_alert=True,
        project_org_id=None,
    ):
        from prowler.providers.gcp.models import GCPOrganization, GCPProject
        from prowler.providers.gcp.services.logging.logging_service import Metric, Sink
        from prowler.providers.gcp.services.monitoring.monitoring_service import (
            AlertPolicy,
        )

        bucket_name = self.BUCKET if bucket_name is None else bucket_name
        sink_destination = (
            f"logging.googleapis.com/{self.BUCKET}"
            if sink_destination is None
            else sink_destination
        )
        project_org_id = self.ORG if project_org_id is None else project_org_id

        logging_client = MagicMock()
        logging_client.project_ids = [GCP_PROJECT_ID]
        logging_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="child",
                labels={},
                lifecycle_state="ACTIVE",
                organization=GCPOrganization(
                    id=project_org_id, name=f"organizations/{project_org_id}"
                ),
            )
        }
        logging_client.metrics = [
            Metric(
                name="central-metric",
                type="logging.googleapis.com/user/central-metric",
                filter=self.FILTER,
                project_id="central-logging-project",
                bucket_name=bucket_name,
            )
        ]
        logging_client.sinks = [
            Sink(
                name="org-sink",
                destination=sink_destination,
                filter="all",
                project_id=f"organizations/{self.ORG}",
                include_children=include_children,
            )
        ]
        monitoring_client = MagicMock()
        monitoring_client.alert_policies = (
            [
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
            if with_alert
            else []
        )
        return logging_client, monitoring_client

    def _run(self, logging_client, monitoring_client):
        from prowler.providers.gcp.services.logging.logging_service import (
            get_projects_covered_by_aggregated_metric,
        )

        return get_projects_covered_by_aggregated_metric(
            logging_client, monitoring_client, self.FILTER
        )

    def test_covered_when_all_conditions_met(self):
        logging_client, monitoring_client = self._clients()
        assert self._run(logging_client, monitoring_client) == {
            GCP_PROJECT_ID: "central-metric"
        }

    def test_not_covered_without_alert(self):
        logging_client, monitoring_client = self._clients(with_alert=False)
        assert self._run(logging_client, monitoring_client) == {}

    def test_not_covered_when_metric_not_bucket_scoped(self):
        logging_client, monitoring_client = self._clients(bucket_name="")
        assert self._run(logging_client, monitoring_client) == {}

    def test_not_covered_when_sink_not_include_children(self):
        logging_client, monitoring_client = self._clients(include_children=False)
        assert self._run(logging_client, monitoring_client) == {}

    def test_not_covered_when_sink_destination_bucket_differs(self):
        logging_client, monitoring_client = self._clients(
            sink_destination="logging.googleapis.com/projects/x/locations/eu/buckets/other"
        )
        assert self._run(logging_client, monitoring_client) == {}

    def test_not_covered_when_project_org_differs(self):
        logging_client, monitoring_client = self._clients(project_org_id="999999999")
        assert self._run(logging_client, monitoring_client) == {}
