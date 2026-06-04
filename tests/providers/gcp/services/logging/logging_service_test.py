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
