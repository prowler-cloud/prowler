from googleapiclient.errors import HttpError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class AppEngine(GCPService):
    """App Engine Admin API client exposing every service version per project."""

    def __init__(self, provider: GcpProvider) -> None:
        super().__init__("appengine", provider)
        self.versions = []
        self._get_versions()

    def _get_versions(self) -> None:
        for project_id in self.project_ids:
            try:
                app = (
                    self.client.apps()
                    .get(appsId=project_id)
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
            except HttpError as http_error:
                # 404 means the API is enabled but no App Engine application exists
                if http_error.resp.status == 404:
                    logger.warning(
                        f"{project_id} -- App Engine API is enabled but no application exists"
                    )
                else:
                    logger.error(
                        f"{project_id} -- {http_error.__class__.__name__}[{http_error.__traceback__.tb_lineno}]: {http_error}"
                    )
                continue
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue

            location = app.get("locationId", "")
            try:
                services = self.client.apps().services()
                services_request = services.list(appsId=project_id)
                while services_request is not None:
                    services_response = services_request.execute(
                        num_retries=DEFAULT_RETRY_ATTEMPTS
                    )
                    for service in services_response.get("services", []):
                        service_id = service.get("id", "")
                        self._get_service_versions(project_id, location, service_id)
                    services_request = services.list_next(
                        previous_request=services_request,
                        previous_response=services_response,
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_service_versions(
        self, project_id: str, location: str, service_id: str
    ) -> None:
        try:
            versions = self.client.apps().services().versions()
            request = versions.list(appsId=project_id, servicesId=service_id)
            while request is not None:
                response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                for version in response.get("versions", []):
                    version_id = version.get("id", "")
                    self.versions.append(
                        Version(
                            id=version.get(
                                "name",
                                f"apps/{project_id}/services/{service_id}/versions/{version_id}",
                            ),
                            name=f"{service_id}/{version_id}",
                            version_id=version_id,
                            service=service_id,
                            project_id=project_id,
                            location=location,
                            runtime=version.get("runtime", ""),
                            env=version.get("env", "standard"),
                            serving_status=version.get("servingStatus", "SERVING"),
                        )
                    )
                request = versions.list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Version(BaseModel):
    """App Engine service version consumed by GCP checks."""

    id: str
    name: str
    version_id: str
    service: str
    project_id: str
    location: str
    runtime: str
    env: str = "standard"
    serving_status: str = "SERVING"
