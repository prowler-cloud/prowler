from __future__ import annotations

from dataclasses import dataclass
from typing import List

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class Keystone(OpenStackService):
    """Service wrapper using openstacksdk identity APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.identity
        self.projects: List[KeystoneProject] = []
        self._list_projects()

    def _list_projects(self) -> None:
        """List all Keystone projects in the current OpenStack deployment."""
        logger.info("Keystone - Listing projects...")
        try:
            for project in self.client.projects():
                self.projects.append(
                    KeystoneProject(
                        id=getattr(project, "id", ""),
                        name=getattr(project, "name", ""),
                        domain_id=getattr(project, "domain_id", ""),
                        enabled=getattr(project, "is_enabled", True),
                        description=getattr(project, "description", ""),
                        region=self.region,
                        project_id=self.project_id,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to list Keystone projects: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error listing Keystone projects: {error}"
            )


@dataclass
class KeystoneProject:
    """Represents an OpenStack Keystone project."""

    id: str
    name: str
    domain_id: str
    enabled: bool
    description: str
    region: str
    project_id: str
