from unittest.mock import patch

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

            assert GCP_PROJECT_ID in logging_client.compute_audit_entries
            assert len(logging_client.compute_audit_entries[GCP_PROJECT_ID]) == 1

            audit_entry = logging_client.compute_audit_entries[GCP_PROJECT_ID][0]
            assert audit_entry.insert_id == "audit-log-entry-1"
            assert audit_entry.timestamp == "2024-01-15T10:30:00Z"
            assert audit_entry.resource_type == "gce_instance"
            assert audit_entry.resource_name == "test-instance-1"
            assert audit_entry.method_name == "v1.compute.instances.insert"
            assert audit_entry.service_name == "compute.googleapis.com"
            assert audit_entry.principal_email == "user@example.com"
            assert audit_entry.caller_ip == "192.168.1.1"
            assert audit_entry.project_id == GCP_PROJECT_ID
