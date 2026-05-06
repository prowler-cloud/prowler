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
_CONNECTOR = f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/connectors/my-connector"


def _make_cloudfunction_client(functions_list, iam_bindings=None):
    """Return a mock GCP API client for the Cloud Functions v2 service."""
    client = MagicMock()

    # locations().list()
    client.projects().locations().list().execute.return_value = {
        "locations": [{"locationId": _LOCATION_ID}]
    }
    client.projects().locations().list_next.return_value = None

    # locations().functions().list()
    client.projects().locations().functions().list().execute.return_value = {
        "functions": functions_list
    }
    client.projects().locations().functions().list_next.return_value = None

    # IAM policy per-function
    iam_response = {"bindings": iam_bindings or []}

    def mock_get_iam_policy(resource):
        rv = MagicMock()
        rv.execute.return_value = iam_response
        return rv

    client.projects().locations().functions().getIamPolicy = mock_get_iam_policy

    return client


class TestCloudFunctionService:
    def test_get_functions_with_vpc_connector(self):
        """Service parses vpc_connector from serviceConfig."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/{_FUNCTION_NAME}",
                        "state": "ACTIVE",
                        "serviceConfig": {
                            "vpcConnector": _CONNECTOR,
                            "ingressSettings": "ALLOW_INTERNAL_ONLY",
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
            assert fn.id == f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/{_FUNCTION_NAME}"
            assert fn.project_id == GCP_PROJECT_ID
            assert fn.location == _LOCATION_ID
            assert fn.state == "ACTIVE"
            assert fn.vpc_connector == _CONNECTOR
            assert fn.ingress_settings == "ALLOW_INTERNAL_ONLY"
            assert fn.publicly_accessible is False

    def test_get_functions_without_vpc_connector(self):
        """Service sets vpc_connector=None when not present in serviceConfig."""

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
            assert fn.ingress_settings == "ALLOW_ALL"

    def test_get_functions_iam_policy_public(self):
        """_get_functions_iam_policy sets publicly_accessible=True when allUsers binding found."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/public-func",
                        "state": "ACTIVE",
                        "serviceConfig": {},
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/cloudfunctions.invoker",
                        "members": ["allUsers"],
                    }
                ],
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
            assert cf_client.functions[0].publicly_accessible is True

    def test_get_functions_iam_policy_all_authenticated_users(self):
        """_get_functions_iam_policy sets publicly_accessible=True when allAuthenticatedUsers binding found."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/auth-users-func",
                        "state": "ACTIVE",
                        "serviceConfig": {},
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/cloudfunctions.invoker",
                        "members": ["allAuthenticatedUsers"],
                    }
                ],
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
            assert cf_client.functions[0].publicly_accessible is True

    def test_get_functions_iam_policy_not_public(self):
        """_get_functions_iam_policy leaves publicly_accessible=False for private functions."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/private-func",
                        "state": "ACTIVE",
                        "serviceConfig": {},
                    }
                ],
                iam_bindings=[
                    {
                        "role": "roles/cloudfunctions.invoker",
                        "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"],
                    }
                ],
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
            assert cf_client.functions[0].publicly_accessible is False
