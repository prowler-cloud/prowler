from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## DNS
class DNS:
    def __init__(self, audit_info):
        self.service = "dns"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.managed_zones = []
        self.__get_managed_zones__()

    def __get_managed_zones__(self):
        try:
            request = self.client.managedZones().list(project=self.project_id)
            while request is not None:
                response = request.execute()
                for managed_zone in response.get("managedZones"):
                    self.managed_zones.append(
                        ManagedZone(
                            name=managed_zone["name"],
                            id=managed_zone["id"],
                            dnssec=managed_zone["dnssecConfig"]["state"] == "on",
                            key_specs=managed_zone["dnssecConfig"]["defaultKeySpecs"],
                        )
                    )

                request = self.client.managedZones().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ManagedZone(BaseModel):
    name: str
    id: str
    dnssec: bool
    key_specs: list
