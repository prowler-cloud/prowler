from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## Compute
class Compute:
    def __init__(self, audit_info):
        self.service = "compute"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.zones = []
        self.instances = []
        self.networks = []
        self.__get_zones__()
        self.__get_instances__()
        self.__get_networks__()

    def __get_zones__(self):
        try:
            request = self.client.zones().list(project=self.project_id)
            while request is not None:
                response = request.execute()

                for zone in response.get("items", []):
                    self.zones.append(zone["name"])

                request = self.client.zones().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_instances__(self):
        try:
            for zone in self.zones:
                request = self.client.instances().list(
                    project=self.project_id, zone=zone
                )
                while request is not None:
                    response = request.execute()

                    for instance in response.get("items", []):
                        public_ip = False
                        for interface in instance["networkInterfaces"]:
                            for config in interface.get("accessConfigs", []):
                                if "natIP" in config:
                                    public_ip = True
                        self.instances.append(
                            Instance(
                                name=instance["name"],
                                id=instance["id"],
                                zone=zone,
                                public_ip=public_ip,
                            )
                        )

                    request = self.client.instances().list_next(
                        previous_request=request, previous_response=response
                    )
        except Exception as error:
            logger.error(
                f"{zone} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_networks__(self):
        try:
            request = self.client.networks().list(project=self.project_id)
            while request is not None:
                response = request.execute()

                for network in response.get("items", []):
                    self.networks.append(
                        Network(
                            name=network["name"],
                            id=network["id"],
                        )
                    )

                request = self.client.networks().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Instance(BaseModel):
    name: str
    id: str
    zone: str
    public_ip: bool


class Network(BaseModel):
    name: str
    id: str
