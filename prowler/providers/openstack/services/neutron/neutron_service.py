from __future__ import annotations

from typing import List, Optional

from openstack import exceptions as openstack_exceptions
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class SecurityGroupRule(BaseModel):
    """Represents a Neutron security group rule."""

    id: str
    direction: str
    ethertype: Optional[str] = None
    protocol: Optional[str] = None
    port_range_min: Optional[int] = None
    port_range_max: Optional[int] = None
    remote_ip_prefix: Optional[str] = None


class SecurityGroup(BaseModel):
    """Represents a Neutron security group."""

    id: str
    name: str
    project_id: str
    description: Optional[str] = None
    region: str
    rules: List[SecurityGroupRule] = Field(default_factory=list)


class Neutron(OpenStackService):
    """Wrapper around Neutron networking service."""

    def __init__(self, provider=None) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.network
        self.security_groups: List[SecurityGroup] = []
        self._get_security_groups()

    def _get_security_groups(self) -> None:
        """Fetch all security groups available to the authenticated project."""
        logger.info("Neutron - Retrieving security groups from OpenStack...")
        try:
            for sg in self.client.security_groups():
                rules = [
                    self._build_rule(rule)
                    for rule in getattr(sg, "security_group_rules", [])
                ]
                self.security_groups.append(
                    SecurityGroup(
                        id=getattr(sg, "id", ""),
                        name=getattr(sg, "name", ""),
                        project_id=getattr(sg, "project_id", self.project_id),
                        description=getattr(sg, "description", ""),
                        region=self.region,
                        rules=rules,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- Failed to list Neutron security groups: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- Unexpected error listing Neutron security groups: {error}"
            )

    @staticmethod
    def _build_rule(raw_rule) -> SecurityGroupRule:
        """Normalize a Neutron security group rule resource."""
        if isinstance(raw_rule, dict):
            source = raw_rule
            get = source.get
        else:
            get = getattr
            source = raw_rule

        return SecurityGroupRule(
            id=get(source, "id", ""),
            direction=get(source, "direction", ""),
            ethertype=get(source, "ethertype", None),
            protocol=get(source, "protocol", None),
            port_range_min=get(source, "port_range_min", None),
            port_range_max=get(source, "port_range_max", None),
            remote_ip_prefix=get(source, "remote_ip_prefix", None),
        )
