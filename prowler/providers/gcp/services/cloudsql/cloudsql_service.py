from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService


################## CloudSQL
class CloudSQL(GCPService):
    def __init__(self, audit_info):
        super().__init__("sqladmin", audit_info)
        self.instances = []
        self.__threading_call__(self.__get_instances__, self.project_ids)

    def __get_instances__(self, project_id):
        try:
            request = self.client.instances().list(project=project_id)
            while request is not None:
                response = request.execute(http=self.__get_AuthorizedHttp_client__())

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
                            project_id=project_id,
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
    project_id: str
