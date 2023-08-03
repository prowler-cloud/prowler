from typing import Optional

import google_auth_httplib2
import httplib2
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService


################## KMS
class KMS(GCPService):
    def __init__(self, audit_info):
        super().__init__("cloudkms", audit_info)
        self.locations = []
        self.key_rings = []
        self.crypto_keys = []
        self.__get_locations__()
        self.__location_threading_call__(self.__get_key_rings__)
        self.__get_crypto_keys__()
        self.__get_crypto_keys_iam_policy__()

    def __get_locations__(self):
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

    def __get_key_rings__(self, location):
        try:
            request = (
                self.client.projects().locations().keyRings().list(parent=location.name)
            )
            http = google_auth_httplib2.AuthorizedHttp(
                self.credentials, http=httplib2.Http()
            )
            while request is not None:
                response = request.execute(http=http)

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

    def __get_crypto_keys__(self):
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
                                name=key["name"].split("/")[-1],
                                location=key["name"].split("/")[3],
                                rotation_period=key.get("rotationPeriod"),
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

    def __get_crypto_keys_iam_policy__(self):
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
    name: str
    location: str
    rotation_period: Optional[str]
    key_ring: str
    members: list = []
    project_id: str
