from typing import Optional

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
        self._get_functions()

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
                                            name=fn["name"].split("/")[-1],
                                            project_id=project_id,
                                            location=location_id,
                                            state=fn.get("state", "UNKNOWN"),
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


class Function(BaseModel):
    """Cloud Function resource consumed by GCP checks."""

    name: str
    project_id: str
    location: str
    state: str
    vpc_connector: Optional[str] = None
