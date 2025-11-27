from pydantic.v1 import BaseModel

import prowler.providers.gcp.config as config
from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class AccessContextManager(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("accesscontextmanager", provider, api_version="v1")
        self.service_perimeters = []
        self._get_service_perimeters()

    def _get_service_perimeters(self):
        for org in cloudresourcemanager_client.organizations:
            try:
                access_policies = []
                try:
                    request = self.client.accessPolicies().list(
                        parent=f"organizations/{org.id}"
                    )
                    while request is not None:
                        response = request.execute(
                            num_retries=config.DEFAULT_RETRY_ATTEMPTS
                        )
                        access_policies.extend(response.get("accessPolicies", []))

                        request = self.client.accessPolicies().list_next(
                            previous_request=request, previous_response=response
                        )
                except Exception as error:
                    logger.error(
                        f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue

                for policy in access_policies:
                    try:
                        request = (
                            self.client.accessPolicies()
                            .servicePerimeters()
                            .list(parent=policy["name"])
                        )
                        while request is not None:
                            response = request.execute(
                                num_retries=config.DEFAULT_RETRY_ATTEMPTS
                            )

                            for perimeter in response.get("servicePerimeters", []):
                                status = perimeter.get("status", {})
                                spec = perimeter.get("spec", {})

                                perimeter_config = status if status else spec

                                resources = perimeter_config.get("resources", [])
                                restricted_services = perimeter_config.get(
                                    "restrictedServices", []
                                )

                                self.service_perimeters.append(
                                    ServicePerimeter(
                                        name=perimeter["name"],
                                        title=perimeter.get("title", ""),
                                        perimeter_type=perimeter.get(
                                            "perimeterType", ""
                                        ),
                                        resources=resources,
                                        restricted_services=restricted_services,
                                        policy_name=policy["name"],
                                    )
                                )

                            request = (
                                self.client.accessPolicies()
                                .servicePerimeters()
                                .list_next(
                                    previous_request=request, previous_response=response
                                )
                            )
                    except Exception as error:
                        logger.error(
                            f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )

            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class ServicePerimeter(BaseModel):
    name: str
    title: str
    perimeter_type: str
    resources: list[str]
    restricted_services: list[str]
    policy_name: str
