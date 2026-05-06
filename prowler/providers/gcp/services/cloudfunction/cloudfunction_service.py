from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudFunction(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("cloudfunctions", provider, api_version="v2")
        self.functions = []
        self._get_functions()
        self._get_functions_iam_policy()

    def _get_functions(self):
        for project_id in self.project_ids:
            try:
                locations_request = self.client.projects().locations().list(
                    name=f"projects/{project_id}"
                )
                while locations_request is not None:
                    locations_response = locations_request.execute(
                        num_retries=DEFAULT_RETRY_ATTEMPTS
                    )
                    for location in locations_response.get("locations", []):
                        location_id = location["locationId"]
                        try:
                            request = (
                                self.client.projects()
                                .locations()
                                .functions()
                                .list(
                                    parent=f"projects/{project_id}/locations/{location_id}"
                                )
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
                                            vpc_connector=service_config.get(
                                                "vpcConnector"
                                            ),
                                            ingress_settings=service_config.get(
                                                "ingressSettings", "ALLOW_ALL"
                                            ),
                                        )
                                    )
                                request = (
                                    self.client.projects()
                                    .locations()
                                    .functions()
                                    .list_next(
                                        previous_request=request,
                                        previous_response=response,
                                    )
                                )
                        except Exception as error:
                            logger.error(
                                f"{location_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                    locations_request = (
                        self.client.projects()
                        .locations()
                        .list_next(
                            previous_request=locations_request,
                            previous_response=locations_response,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_functions_iam_policy(self):
        self.__threading_call__(self._get_function_iam_policy, self.functions)

    def _get_function_iam_policy(self, function):
        try:
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
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Function(BaseModel):
    id: str
    name: str
    project_id: str
    location: str
    state: str
    vpc_connector: Optional[str] = None
    ingress_settings: str = "ALLOW_ALL"
    publicly_accessible: bool = False
