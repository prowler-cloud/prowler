from __future__ import annotations

from dataclasses import dataclass
from typing import List

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class Compute(OpenStackService):
    """Service wrapper using openstacksdk compute APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.compute
        self.instances: List[ComputeInstance] = []
        self._list_instances()

    def _list_instances(self) -> None:
        """List all compute instances in the current project."""
        logger.info("Compute - Listing instances...")
        try:
            for server in self.client.servers():
                # Extract security group names (handle None case)
                sg_list = getattr(server, "security_groups", None) or []
                security_groups = [sg.get("name", "") for sg in sg_list]

                self.instances.append(
                    ComputeInstance(
                        id=getattr(server, "id", ""),
                        name=getattr(server, "name", ""),
                        status=getattr(server, "status", ""),
                        flavor_id=getattr(server, "flavor", {}).get("id", ""),
                        security_groups=security_groups,
                        region=self.region,
                        project_id=self.project_id,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to list compute instances: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error listing compute instances: {error}"
            )


@dataclass
class ComputeInstance:
    """Represents an OpenStack compute instance (VM)."""

    id: str
    name: str
    status: str
    flavor_id: str
    security_groups: List[str]
    region: str
    project_id: str
