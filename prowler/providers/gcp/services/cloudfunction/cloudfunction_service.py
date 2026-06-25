from typing import Optional

from googleapiclient import discovery
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudFunction(GCPService):
    """Cloud Functions v2 service client.

    Enumerates Cloud Functions across every accessible project and region
    using the `cloudfunctions.googleapis.com` v2 API and exposes them through
    the `functions` attribute.
    """

    def __init__(self, provider: GcpProvider) -> None:
        """Initialize the service and preload Cloud Functions."""
        super().__init__("cloudfunctions", provider, api_version="v2")
        self.functions = []
        self._run_client = None
        self._get_functions()
        self._get_functions_iam_policy()

    def _get_functions(self) -> None:
        """Fetch Cloud Functions for every project and location."""
        for project_id in self.project_ids:
            try:
                locations = self.client.projects().locations()
                locations_request = locations.list(name=f"projects/{project_id}")
                while locations_request is not None:
                    locations_response = locations_request.execute(
                        num_retries=DEFAULT_RETRY_ATTEMPTS
                    )
                    for location in locations_response.get("locations", []):
                        location_id = location["locationId"]
                        try:
                            functions = locations.functions()
                            request = functions.list(
                                parent=f"projects/{project_id}/locations/{location_id}"
                            )
                            while request is not None:
                                response = request.execute(
                                    num_retries=DEFAULT_RETRY_ATTEMPTS
                                )
                                for fn in response.get("functions", []):
                                    service_config = fn.get("serviceConfig", {})
                                    self.functions.append(
                                        Function(
                                            id=fn["name"],
                                            name=fn["name"].split("/")[-1],
                                            project_id=project_id,
                                            location=location_id,
                                            state=fn.get("state", "UNKNOWN"),
                                            environment=fn.get("environment", "GEN_1"),
                                            service=service_config.get("service"),
                                            vpc_connector=service_config.get(
                                                "vpcConnector"
                                            ),
                                        )
                                    )
                                request = functions.list_next(
                                    previous_request=request,
                                    previous_response=response,
                                )
                        except Exception as error:
                            logger.error(
                                f"{location_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                    locations_request = locations.list_next(
                        previous_request=locations_request,
                        previous_response=locations_response,
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_functions_iam_policy(self) -> None:
        """Fetch IAM policy for every Cloud Function in parallel.

        For gen2 functions, IAM is delegated to the underlying Cloud Run
        service, so a `run.googleapis.com` v2 client is required.
        """
        if any(f.environment == "GEN_2" for f in self.functions):
            self._run_client = discovery.build(
                "run",
                "v2",
                credentials=self.credentials,
                num_retries=DEFAULT_RETRY_ATTEMPTS,
            )
        self.__threading_call__(self._get_function_iam_policy, self.functions)

    def _get_function_iam_policy(self, function: "Function") -> None:
        """Mark a Cloud Function as publicly accessible when bound to `allUsers` or `allAuthenticatedUsers`.

        Cloud Functions gen2 delegates invocation IAM to its backing Cloud Run
        service, so the binding is queried via the Run API. Gen1 functions are
        queried through the Cloud Functions API directly.
        """
        try:
            if function.environment == "GEN_2" and function.service:
                response = (
                    self._run_client.projects()
                    .locations()
                    .services()
                    .getIamPolicy(resource=function.service)
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
            else:
                response = (
                    self.client.projects()
                    .locations()
                    .functions()
                    .getIamPolicy(resource=function.id)
                    .execute(
                        http=self.__get_AuthorizedHttp_client__(),
                        num_retries=DEFAULT_RETRY_ATTEMPTS,
                    )
                )
            for binding in response.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    function.publicly_accessible = True
                    break
        except Exception as error:
            logger.error(
                f"{function.location} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Function(BaseModel):
    """Cloud Function resource consumed by GCP checks."""

    id: str
    name: str
    project_id: str
    location: str
    state: str
    environment: str = "GEN_1"
    service: Optional[str] = None
    vpc_connector: Optional[str] = None
    publicly_accessible: bool = False
