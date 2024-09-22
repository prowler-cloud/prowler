from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


################## DNS
class DNS(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.managed_zones = []
        self._get_managed_zones()
        self.policies = []
        self._get_policies()

    def _get_managed_zones(self):
        for project_id in self.project_ids:
            try:
                request = self.client.managedZones().list(project=project_id)
                while request is not None:
                    response = request.execute()
                    for managed_zone in response.get("managedZones"):
                        self.managed_zones.append(
                            ManagedZone(
                                name=managed_zone["name"],
                                id=managed_zone["id"],
                                dnssec=managed_zone.get("dnssecConfig", {})["state"]
                                == "on",
                                key_specs=managed_zone.get("dnssecConfig", {})[
                                    "defaultKeySpecs"
                                ],
                                project_id=project_id,
                            )
                        )

                    request = self.client.managedZones().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_policies(self):
        for project_id in self.project_ids:
            try:
                request = self.client.policies().list(project=project_id)
                while request is not None:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        policy_networks = []
                        for network in policy.get("networks", []):
                            policy_networks.append(network["networkUrl"].split("/")[-1])
                        self.policies.append(
                            Policy(
                                name=policy["name"],
                                id=policy["id"],
                                logging=policy.get("enableLogging", False),
                                networks=policy_networks,
                                project_id=project_id,
                            )
                        )

                    request = self.client.policies().list_next(
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
    project_id: str


class Policy(BaseModel):
    name: str
    id: str
    logging: bool
    networks: list
    project_id: str
