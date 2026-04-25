from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class SecretManager(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("secretmanager", provider)
        self.secrets = []
        self._get_secrets()
        self._get_secrets_iam_policy()

    def _get_secrets(self):
        for project_id in self.project_ids:
            try:
                request = self.client.projects().secrets().list(
                    parent=f"projects/{project_id}"
                )
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for secret in response.get("secrets", []):
                        rotation = secret.get("rotation", {})
                        self.secrets.append(
                            Secret(
                                id=secret["name"],
                                name=secret["name"].split("/")[-1],
                                project_id=project_id,
                                rotation_period=rotation.get("rotationPeriod"),
                                next_rotation_time=rotation.get("nextRotationTime"),
                            )
                        )
                    request = (
                        self.client.projects()
                        .secrets()
                        .list_next(
                            previous_request=request, previous_response=response
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_secrets_iam_policy(self):
        self.__threading_call__(self._get_secret_iam_policy, self.secrets)

    def _get_secret_iam_policy(self, secret):
        try:
            response = (
                self.client.projects()
                .secrets()
                .getIamPolicy(resource=secret.id)
                .execute(
                    http=self.__get_AuthorizedHttp_client__(),
                    num_retries=DEFAULT_RETRY_ATTEMPTS,
                )
            )
            for binding in response.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    secret.publicly_accessible = True
                    break
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Secret(BaseModel):
    id: str
    name: str
    project_id: str
    location: str = "global"
    rotation_period: Optional[str] = None
    next_rotation_time: Optional[str] = None
    publicly_accessible: bool = False
