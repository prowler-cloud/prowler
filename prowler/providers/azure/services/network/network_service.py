from dataclasses import dataclass

from azure.mgmt.network import NetworkManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## SQLServer
class Network(AzureService):
    def __init__(self, audit_info):
        super().__init__(NetworkManagementClient, audit_info)
        self.security_groups = self.__get_security_groups__()

    def __get_security_groups__(self):
        logger.info("SQL Server - Getting Network Security Groups...")
        security_groups = {}
        for subscription, client in self.clients.items():
            try:
                security_groups.update({subscription: []})
                security_groups_list = client.network_security_groups.list_all()
                for security_group in security_groups_list:
                    security_groups[subscription].append(
                        SecurityGroup(
                            id=security_group.id,
                            name=security_group.name,
                            location=security_group.location,
                            security_rules=security_group.security_rules,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_groups


@dataclass
class SecurityGroup:
    id: str
    name: str
    location: str
    security_rules: list
