from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## KMS
class KMS(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("cloudkms", provider)
        self.locations = []
        self.key_rings = []
        self.crypto_keys = []
        self._get_locations()
        self.__threading_call__(self._get_key_rings, self.locations)
        self._get_crypto_keys()
        self._get_crypto_keys_iam_policy()

    def _get_locations(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .list(name="projects/" + project_id)
                )
                while request is not None:
                    response = request.execute()

                    for location in response["locations"]:
                        self.locations.append(
                            KeyLocation(name=location["name"], project_id=project_id)
                        )

                    request = (
                        self.client.projects()
                        .locations()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_key_rings(self, location):
        try:
            request = (
                self.client.projects().locations().keyRings().list(parent=location.name)
            )
            while request is not None:
                response = request.execute(http=self.__get_AuthorizedHttp_client__())

                for ring in response.get("keyRings", []):
                    self.key_rings.append(
                        KeyRing(
                            name=ring["name"],
                            project_id=location.project_id,
                        )
                    )

                request = (
                    self.client.projects()
                    .locations()
                    .keyRings()
                    .list_next(previous_request=request, previous_response=response)
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_crypto_keys(self):
        for ring in self.key_rings:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .keyRings()
                    .cryptoKeys()
                    .list(parent=ring.name)
                )
                while request is not None:
                    response = request.execute()

                    for key in response.get("cryptoKeys", []):
                        self.crypto_keys.append(
                            CriptoKey(
                                id=key["name"],
                                name=key["name"].split("/")[-1],
                                location=key["name"].split("/")[3],
                                rotation_period=key.get("rotationPeriod"),
                                next_rotation_time=key.get("nextRotationTime"),
                                key_ring=ring.name,
                                project_id=ring.project_id,
                            )
                        )

                    request = (
                        self.client.projects()
                        .locations()
                        .keyRings()
                        .cryptoKeys()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_crypto_keys_iam_policy(self):
        for key in self.crypto_keys:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .keyRings()
                    .cryptoKeys()
                    .getIamPolicy(resource=key.key_ring + "/cryptoKeys/" + key.name)
                )
                response = request.execute()

                for binding in response.get("bindings", []):
                    key.members.extend(binding.get("members", []))
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class KeyLocation(BaseModel):
    name: str
    project_id: str


class KeyRing(BaseModel):
    name: str
    project_id: str


class CriptoKey(BaseModel):
    id: str
    name: str
    location: str
    rotation_period: Optional[str]
    next_rotation_time: Optional[str]
    key_ring: str
    members: list = []
    project_id: str
