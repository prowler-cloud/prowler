from typing import Dict, List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class Lightsail(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.instances = self.__list_instances__()
        self.databases = self.__list_databases__()

    def __list_instances__(self) -> list:
        logger.info("Lightsail - Listing instances...")
        instance_list = []
        try:
            instances = self.client.get_instances()

            for instance in instances["instances"]:
                ports = []

                for port_range in instance.get("networking", {}).get("ports", []):
                    ports.append(
                        PortRange(
                            range=(
                                (
                                    port_range.get("fromPort", "")
                                    if port_range.get("fromPort", "")
                                    == port_range.get("toPort", "")
                                    else f"{port_range.get('fromPort', '')}-{port_range.get('toPort', '')}"
                                )
                                if port_range.get("fromPort", "")
                                else ""
                            ),
                            protocol=port_range.get("protocol", ""),
                            access_from=port_range.get("accessFrom", ""),
                            access_type=port_range.get("accessType", ""),
                        )
                    )

                auto_snapshot_enabled = False
                for add_on in instance.get("addOns", []):
                    if (
                        add_on.get("name") == "AutoSnapshot"
                        and add_on.get("status") == "Enabled"
                    ):
                        auto_snapshot_enabled = True
                        break

                instance_list.append(
                    Instance(
                        name=instance.get("name", ""),
                        arn=instance.get("arn", ""),
                        tags=instance.get("tags", []),
                        location=instance.get("location", ""),
                        static_ip=instance.get("isStaticIp", ""),
                        public_ip=instance.get("publicIpAddress", ""),
                        private_ip=instance.get("privateIpAddress", ""),
                        ipv6_addresses=instance.get("ipv6Addresses", []),
                        ip_address_type=instance.get("ipAddressType", "ipv4"),
                        ports=ports,
                        auto_snapshot=auto_snapshot_enabled,
                    )
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return instance_list

    def __list_databases__(self) -> list:
        logger.info("Lightsail - Listing databases...")
        database_list = []
        try:
            databases = self.client.get_relational_databases()

            for database in databases.get("relationalDatabases", []):
                database_list.append(
                    Database(
                        name=database.get("name", ""),
                        arn=database.get("arn", ""),
                        tags=database.get("tags", []),
                        location=database.get("location", ""),
                        engine=database.get("engine", ""),
                        engine_version=database.get("engineVersion", ""),
                        status=database.get("state", ""),
                        username=database.get("masterUsername", ""),
                        public_access=database.get("publiclyAccessible", ""),
                    )
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return database_list


class PortRange(BaseModel):
    range: str
    protocol: str
    access_from: str
    access_type: str


class Instance(BaseModel):
    name: str
    arn: str
    tags: List[Dict[str, str]]
    location: dict
    static_ip: bool
    public_ip: str
    private_ip: str
    ipv6_addresses: List[str]
    ip_address_type: str
    ports: List[PortRange]
    auto_snapshot: bool


class Database(BaseModel):
    name: str
    arn: str
    tags: List[Dict[str, str]]
    location: dict
    engine: str
    engine_version: str
    status: str
    username: str
    public_access: bool
