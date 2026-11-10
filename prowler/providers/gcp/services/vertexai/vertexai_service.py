from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService

# Workbench metadata key that controls sudo access for the notebook user.
ROOT_ACCESS_DISABLED_METADATA_KEY = "notebook-disable-root"
# Workbench metadata key that removes the JupyterLab terminal.
TERMINAL_ACCESS_DISABLED_METADATA_KEY = "notebook-disable-terminal"
# Workbench metadata key that blocks file downloads from the JupyterLab UI.
FILE_DOWNLOAD_DISABLED_METADATA_KEY = "notebook-disable-downloads"
# Workbench metadata key holding the Unix-cron schedule for automatic upgrades.
UPGRADE_SCHEDULE_METADATA_KEY = "notebook-upgrade-schedule"


def _metadata_flag_enabled(metadata: dict, key: str) -> bool:
    """Return True when a boolean Workbench metadata key is set to `true`."""
    return str(metadata.get(key, "")).lower() == "true"


class VertexAI(GCPService):
    """Vertex AI service client.

    Enumerates Vertex AI Workbench instances across every accessible project
    using the `notebooks.googleapis.com` v2 API and exposes them through the
    `workbench_instances` attribute.
    """

    def __init__(self, provider: GcpProvider) -> None:
        """Initialize the service and preload Workbench instances."""
        super().__init__("notebooks", provider, api_version="v2")
        self.workbench_instances = []
        self._get_workbench_instances()

    def _get_workbench_instances(self) -> None:
        """Fetch Workbench instances for every project across all locations."""
        for project_id in self.project_ids:
            try:
                instances = self.client.projects().locations().instances()
                request = instances.list(parent=f"projects/{project_id}/locations/-")
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for instance in response.get("instances", []):
                        gce_setup = instance.get("gceSetup", {})
                        metadata = gce_setup.get("metadata", {})
                        network_interfaces = gce_setup.get("networkInterfaces", [])
                        # Name format: projects/{project}/locations/{zone}/instances/{instance}
                        name_parts = instance["name"].split("/")
                        self.workbench_instances.append(
                            WorkbenchInstance(
                                id=instance["name"],
                                name=name_parts[-1],
                                project_id=project_id,
                                location=name_parts[3],
                                state=instance.get("state", "STATE_UNSPECIFIED"),
                                public_ip_disabled=gce_setup.get(
                                    "disablePublicIp", False
                                ),
                                root_access_disabled=_metadata_flag_enabled(
                                    metadata, ROOT_ACCESS_DISABLED_METADATA_KEY
                                ),
                                terminal_access_disabled=_metadata_flag_enabled(
                                    metadata, TERMINAL_ACCESS_DISABLED_METADATA_KEY
                                ),
                                file_download_disabled=_metadata_flag_enabled(
                                    metadata, FILE_DOWNLOAD_DISABLED_METADATA_KEY
                                ),
                                upgrade_schedule=(
                                    str(
                                        metadata.get(UPGRADE_SCHEDULE_METADATA_KEY, "")
                                    ).strip()
                                    or None
                                ),
                                network=(
                                    network_interfaces[0].get("network")
                                    if network_interfaces
                                    else None
                                ),
                            )
                        )
                    # The wildcard list reports locations it could not reach
                    # instead of raising, so the project was not fully scanned.
                    unreachable = response.get("unreachable", [])
                    if unreachable:
                        logger.error(
                            f"{project_id} -- Workbench instances could not be listed in unreachable locations: {', '.join(unreachable)}"
                        )
                    request = instances.list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{project_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class WorkbenchInstance(BaseModel):
    """Vertex AI Workbench instance resource consumed by GCP checks."""

    id: str
    name: str
    project_id: str
    location: str
    state: str
    public_ip_disabled: bool = False
    root_access_disabled: bool = False
    terminal_access_disabled: bool = False
    file_download_disabled: bool = False
    upgrade_schedule: Optional[str] = None
    network: Optional[str] = None
