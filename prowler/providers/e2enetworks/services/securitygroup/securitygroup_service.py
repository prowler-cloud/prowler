from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.lib.service.service import E2eNetworksService


class SecurityGroups(E2eNetworksService):
    """Service class for E2E Networks security groups."""

    def __init__(self, provider):
        super().__init__("securitygroup", provider)
        self.security_groups: list[SecurityGroupResource] = []
        self.node_security_groups: list[NodeSecurityGroup] = []
        self._fetch_security_groups()
        self._fetch_node_security_groups()

    def _fetch_security_groups(self):
        for location in self.provider.session.locations:
            try:
                groups = self.client.get_data("/security_group/", location=location)
                if not isinstance(groups, list):
                    continue

                for item in groups:
                    rules = [
                        SecurityGroupRule(
                            id=str(rule.get("id", "")),
                            rule_type=rule.get("rule_type", ""),
                            protocol_name=rule.get("protocol_name", ""),
                            port_range=rule.get("port_range", ""),
                            network=rule.get("network", ""),
                            network_cidr=rule.get("network_cidr", ""),
                        )
                        for rule in item.get("rules", [])
                    ]
                    self.security_groups.append(
                        SecurityGroupResource(
                            id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            location=location,
                            description=item.get("description", ""),
                            is_default=bool(item.get("is_default", False)),
                            is_all_traffic_rule=bool(
                                item.get("is_all_traffic_rule", False)
                            ),
                            rules=rules,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"securitygroup - Error fetching groups in {location} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_node_security_groups(self):
        from prowler.providers.e2enetworks.services.node.node_client import node_client

        for node in node_client.nodes:
            if not node.vm_id:
                continue
            try:
                attached = self.client.get_data(
                    f"/security_group/{node.vm_id}/attach/",
                    location=node.location,
                )
                if not isinstance(attached, list):
                    continue

                for item in attached:
                    rules = [
                        SecurityGroupRule(
                            id=str(rule.get("id", "")),
                            rule_type=rule.get("rule_type", ""),
                            protocol_name=rule.get("protocol_name", ""),
                            port_range=rule.get("port_range", ""),
                            network=rule.get("network", ""),
                            network_cidr=rule.get("network_cidr", ""),
                        )
                        for rule in item.get("rules", [])
                    ]
                    self.node_security_groups.append(
                        NodeSecurityGroup(
                            node_id=node.id,
                            node_name=node.name,
                            vm_id=node.vm_id,
                            location=node.location,
                            security_group_id=str(item.get("id", "")),
                            name=item.get("name", ""),
                            is_default=bool(item.get("is_default", False)),
                            is_all_traffic_rule=bool(
                                item.get("is_all_traffic_rule", False)
                            ),
                            rules=rules,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"securitygroup - Error fetching attached groups for node {node.id} -- "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class SecurityGroupRule(BaseModel):
    id: str
    rule_type: str
    protocol_name: str
    port_range: str
    network: str
    network_cidr: str


class SecurityGroupResource(BaseModel):
    id: str
    name: str
    location: str
    description: str = ""
    is_default: bool = False
    is_all_traffic_rule: bool = False
    rules: list[SecurityGroupRule] = []

    @property
    def resource_id(self) -> str:
        return self.id

    @property
    def resource_name(self) -> str:
        return self.name


class NodeSecurityGroup(BaseModel):
    node_id: str
    node_name: str
    vm_id: str
    location: str
    security_group_id: str
    name: str
    is_default: bool = False
    is_all_traffic_rule: bool = False
    rules: list[SecurityGroupRule] = []

    @property
    def resource_id(self) -> str:
        return f"{self.node_id}:{self.security_group_id}"

    @property
    def resource_name(self) -> str:
        return f"{self.node_name}/{self.name}"
