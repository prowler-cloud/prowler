from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class Instance(BaseModel):
    """Model for a Linode Instance."""

    id: int
    label: str
    region: str
    status: str
    ipv4_public: List[str] = []
    firewalls_count: int = 0
    backups_enabled: bool = False
    disk_encryption: str = "disabled"  # "enabled" or "disabled"
    watchdog_enabled: bool = False
    tags: List[str] = []


class InstanceService(LinodeService):
    """Service to interact with Linode Instances."""

    instances: List[Instance] = []

    def __init__(self, provider):
        super().__init__("instance", provider)
        self._describe_instances()

    def _describe_instances(self):
        """Fetch all Linode instances with firewall and IP details."""
        try:
            raw_instances = self.client.linode.instances()
            for inst in raw_instances:
                try:
                    # Count firewalls attached to this instance
                    firewalls_count = 0
                    try:
                        firewalls = inst.firewalls()
                        firewalls_count = len(list(firewalls))
                    except Exception as error:
                        logger.warning(
                            f"instance - Unable to fetch firewalls for instance {inst.id}: {error}"
                        )

                    # Get public IPv4 addresses
                    ipv4_public = []
                    try:
                        for ip in inst.ipv4:
                            ipv4_public.append(str(ip))
                    except Exception:
                        pass

                    # Get backup status
                    backups_enabled = False
                    try:
                        backups = getattr(inst, "backups", None)
                        if backups:
                            backups_enabled = (
                                getattr(backups, "enabled", False) or False
                            )
                    except Exception:
                        pass

                    # Get disk encryption status
                    disk_encryption = "disabled"
                    try:
                        de = getattr(inst, "disk_encryption", None)
                        if de:
                            disk_encryption = str(de)
                    except Exception:
                        pass

                    # Get watchdog status
                    watchdog_enabled = False
                    try:
                        watchdog_enabled = getattr(inst, "watchdog_enabled", False)
                        if watchdog_enabled is None:
                            watchdog_enabled = False
                    except Exception:
                        pass

                    self.instances.append(
                        Instance(
                            id=inst.id,
                            label=inst.label or f"linode-{inst.id}",
                            region=(
                                inst.region.id
                                if hasattr(inst.region, "id")
                                else str(inst.region)
                            ),
                            status=inst.status or "unknown",
                            ipv4_public=ipv4_public,
                            firewalls_count=firewalls_count,
                            backups_enabled=backups_enabled,
                            disk_encryption=disk_encryption,
                            watchdog_enabled=watchdog_enabled,
                            tags=inst.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"instance - Error processing instance {inst.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"instance - Error fetching instances: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
