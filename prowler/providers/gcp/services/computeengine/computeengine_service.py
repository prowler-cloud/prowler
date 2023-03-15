from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client, get_gcp_available_zones


################## ComputeEngine
class ComputeEngine:
    def __init__(self, audit_info):
        self.service = "compute"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.zones = (
            get_gcp_available_zones()
            if not audit_info.audit_zones
            else audit_info.audit_zones
        )
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.instances = []
        self.__get_instances__()

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


class Instance(BaseModel):
    name: str
    id: str
    zone: str
    public_ip: bool
