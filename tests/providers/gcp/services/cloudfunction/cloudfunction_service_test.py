from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
    CloudFunction,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)

_LOCATION_ID = "us-central1"
_FUNCTION_NAME = "my-function"
_CONNECTOR = (
    f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/connectors/my-connector"
)


def _make_cloudfunction_client(functions_list):
    """Return a mock GCP API client for the Cloud Functions v2 service."""
    client = MagicMock()

    client.projects().locations().list().execute.return_value = {
        "locations": [{"locationId": _LOCATION_ID}]
    }
    client.projects().locations().list_next.return_value = None

    client.projects().locations().functions().list().execute.return_value = {
        "functions": functions_list
    }
    client.projects().locations().functions().list_next.return_value = None

    return client


class TestCloudFunctionService:
    def test_get_functions_with_vpc_connector(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/{_FUNCTION_NAME}",
                        "state": "ACTIVE",
                        "serviceConfig": {
                            "vpcConnector": _CONNECTOR,
                        },
                    }
                ]
            )

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
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            fn = cf_client.functions[0]
            assert fn.name == _FUNCTION_NAME
            assert fn.project_id == GCP_PROJECT_ID
            assert fn.location == _LOCATION_ID
            assert fn.state == "ACTIVE"
            assert fn.vpc_connector == _CONNECTOR

    def test_get_functions_without_vpc_connector(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/no-vpc-func",
                        "state": "ACTIVE",
                        "serviceConfig": {},
                    }
                ]
            )

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
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            fn = cf_client.functions[0]
            assert fn.name == "no-vpc-func"
            assert fn.vpc_connector is None
