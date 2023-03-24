from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## CloudSQL
class CloudSQL:
    def __init__(self, audit_info):
        self.service = "sqladmin"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.instances = []
        self.__get_instances__()

    def __get_instances__(self):
        try:
            request = self.client.instances().list(project=self.project_id)
            while request is not None:
                response = request.execute()

                for instance in response.get("items", []):
                    public_ip = False
                    for address in instance.get("ipAddresses", []):
                        if address["type"] == "PRIMARY":
                            public_ip = True
                    self.instances.append(
                        Instance(
                            name=instance["name"],
                            version=instance["databaseVersion"],
                            region=instance["region"],
                            ip_addresses=instance.get("ipAddresses", []),
                            public_ip=public_ip,
                            ssl=instance["settings"]["ipConfiguration"].get(
                                "requireSsl", False
                            ),
                            automated_backups=instance["settings"][
                                "backupConfiguration"
                            ]["enabled"],
                            authorized_networks=instance["settings"]["ipConfiguration"][
                                "authorizedNetworks"
                            ],
                            flags=instance["settings"].get("databaseFlags", []),
                        )
                    )

                request = self.client.instances().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Instance(BaseModel):
    name: str
    version: str
    ip_addresses: list
    region: str
    public_ip: bool
    authorized_networks: list
    ssl: bool
    automated_backups: bool
    flags: list
