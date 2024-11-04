from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Transfer(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.servers = {}
        self.__threading_call__(self._list_servers)
        self.__threading_call__(self._describe_server, self.servers.values())

    def _list_servers(self, regional_client):
        logger.info("Transfer - Listing Transfer Servers...")
        try:
            list_servers_paginator = regional_client.get_paginator("list_servers")
            for page in list_servers_paginator.paginate():
                for server in page["Servers"]:
                    arn = server["Arn"]
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.servers[arn] = Server(
                            arn=arn,
                            id=server.get("ServerId", ""),
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_server(self, server):
        logger.info(f"Transfer - Describing Server {server.id}...")
        try:
            server_description = (
                self.regional_clients[server.region]
                .describe_server(ServerId=server.id)
                .get("Server", {})
            )
            for protocol in server_description.get("Protocols", []):
                server.protocols.append(Protocol(protocol))
            server.tags = server_description.get("Tags", [])
        except Exception as error:
            logger.error(
                f"{server.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Protocol(Enum):
    FTP = "FTP"
    FTPS = "FTPS"
    SFTP = "SFTP"
    AS2 = "AS2"


class Server(BaseModel):
    arn: str
    id: str
    region: str
    protocols: List[Protocol] = Field(default_factory=list)
    tags: List[Dict[str, str]] = Field(default_factory=list)
