from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## KMS
class KMS:
    def __init__(self, audit_info):
        self.service = "cloudkms"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.region = "global"
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.locations = []
        self.key_rings = []
        self.crypto_keys = []
        self.__get_locations__()
        self.__get_key_rings__()
        self.__get_crypto_keys__()

    def __get_client__(self):
        return self.client

    def __get_locations__(self):
        try:
            request = (
                self.client.projects()
                .locations()
                .list(name="projects/" + self.project_id)
            )
            while request is not None:
                response = request.execute()

                for location in response["locations"]:
                    self.locations.append(location["name"])

                request = (
                    self.client.projects()
                    .locations()
                    .list_next(previous_request=request, previous_response=response)
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_key_rings__(self):
        try:
            for location in self.locations:
                request = (
                    self.client.projects().locations().keyRings().list(parent=location)
                )
                while request is not None:
                    response = request.execute()

                    for ring in response.get("keyRings", []):
                        self.key_rings.append(
                            KeyRing(
                                name=ring["name"],
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
        try:
            for ring in self.key_rings:
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


class KeyRing(BaseModel):
    name: str


class CriptoKey(BaseModel):
    name: str
    location: str
    rotation_period: Optional[str]
