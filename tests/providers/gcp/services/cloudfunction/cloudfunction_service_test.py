from unittest.mock import MagicMock, patch

from prowler.providers.gcp.lib.service.service import GCPService
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
_FUNCTION_ID = (
    f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/{_FUNCTION_NAME}"
)
_RUN_SERVICE = (
    f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/services/{_FUNCTION_NAME}"
)
_CONNECTOR = (
    f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/connectors/my-connector"
)


def _make_cloudfunction_client(functions_list, iam_bindings=None):
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

    iam_response = {"bindings": iam_bindings or []}

    def mock_get_iam_policy(resource):
        rv = MagicMock()
        rv.execute.return_value = iam_response
        return rv

    client.projects().locations().functions().getIamPolicy = mock_get_iam_policy

    return client


def _make_run_client(iam_bindings=None):
    """Return a mock Cloud Run v2 client for gen2 IAM policy lookups."""
    client = MagicMock()
    iam_response = {"bindings": iam_bindings or []}

    def mock_get_iam_policy(resource):
        rv = MagicMock()
        rv.execute.return_value = iam_response
        return rv

    client.projects().locations().services().getIamPolicy = mock_get_iam_policy
    return client


class TestCloudFunctionService:
    def test_get_functions_with_vpc_connector(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {
                            "service": _RUN_SERVICE,
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=_make_run_client(),
            ),
        ):
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            fn = cf_client.functions[0]
            assert fn.id == _FUNCTION_ID
            assert fn.name == _FUNCTION_NAME
            assert fn.project_id == GCP_PROJECT_ID
            assert fn.location == _LOCATION_ID
            assert fn.state == "ACTIVE"
            assert fn.environment == "GEN_2"
            assert fn.service == _RUN_SERVICE
            assert fn.vpc_connector == _CONNECTOR
            assert fn.publicly_accessible is False

    def test_get_functions_without_vpc_connector(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/functions/no-vpc-func",
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {
                            "service": f"projects/{GCP_PROJECT_ID}/locations/{_LOCATION_ID}/services/no-vpc-func",
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=_make_run_client(),
            ),
        ):
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            fn = cf_client.functions[0]
            assert fn.name == "no-vpc-func"
            assert fn.vpc_connector is None
            assert fn.publicly_accessible is False

    def test_get_functions_iam_policy_gen2_uses_per_request_http(self):
        """Regression: the gen2 IAM lookup must pass a per-request HTTP client.

        _get_function_iam_policy runs once per function across a thread pool
        (GCPService.__threading_call__), and httplib2 is not thread-safe. The
        gen1 branch isolates each thread with its own AuthorizedHttp via
        __get_AuthorizedHttp_client__; the gen2 branch must do the same. Sharing
        the single self._run_client transport across threads corrupts the
        process heap and aborts the scan (SIGABRT/SIGSEGV).
        """
        sentinel_http = object()

        request = MagicMock()
        request.execute.return_value = {"bindings": []}
        run_client = MagicMock()
        run_client.projects().locations().services().getIamPolicy.return_value = (
            request
        )

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {"service": _RUN_SERVICE},
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=run_client,
            ),
            patch.object(
                GCPService,
                "__get_AuthorizedHttp_client__",
                return_value=sentinel_http,
            ),
        ):
            CloudFunction(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

        # gen2 IAM policy must be fetched with a per-request http (not the shared
        # self._run_client transport), mirroring the gen1 branch.
        request.execute.assert_called_once()
        assert request.execute.call_args.kwargs.get("http") is sentinel_http

    def test_get_functions_iam_policy_gen2_all_users(self):
        """Gen2 functions: allUsers binding lives on the Cloud Run service."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {"service": _RUN_SERVICE},
                    }
                ]
            )

        run_client = _make_run_client(
            iam_bindings=[
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=run_client,
            ),
        ):
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            assert cf_client.functions[0].publicly_accessible is True

    def test_get_functions_iam_policy_gen2_all_authenticated_users(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {"service": _RUN_SERVICE},
                    }
                ]
            )

        run_client = _make_run_client(
            iam_bindings=[
                {
                    "role": "roles/run.invoker",
                    "members": ["allAuthenticatedUsers"],
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=run_client,
            ),
        ):
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            assert cf_client.functions[0].publicly_accessible is True

    def test_get_functions_iam_policy_gen2_not_public(self):
        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_2",
                        "serviceConfig": {"service": _RUN_SERVICE},
                    }
                ]
            )

        run_client = _make_run_client(
            iam_bindings=[
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"],
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
            patch(
                "prowler.providers.gcp.services.cloudfunction.cloudfunction_service.discovery.build",
                return_value=run_client,
            ),
        ):
            cf_client = CloudFunction(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert len(cf_client.functions) == 1
            assert cf_client.functions[0].publicly_accessible is False

    def test_get_functions_iam_policy_gen1_all_users(self):
        """Gen1 functions: IAM binding lives on the Cloud Functions resource itself."""

        def mock_api_client(*args, **kwargs):
            return _make_cloudfunction_client(
                functions_list=[
                    {
                        "name": _FUNCTION_ID,
                        "state": "ACTIVE",
                        "environment": "GEN_1",
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
            assert cf_client.functions[0].environment == "GEN_1"
            assert cf_client.functions[0].publicly_accessible is True
