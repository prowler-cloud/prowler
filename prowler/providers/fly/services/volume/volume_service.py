from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.fly.lib.service.service import FlyService


class FlyVolume(BaseModel):
    """A Fly.io volume and its persistence configuration."""

    id: str
    name: str
    app_name: str
    org_slug: str
    region: str = "global"
    state: str = ""
    size_gb: int = 0
    encrypted: bool = False
    auto_backup_enabled: bool = False
    snapshot_retention: int = 0
    attached_machine_id: Optional[str] = None


class Volume(FlyService):
    """Retrieve Fly.io volumes with their encryption and backup configuration."""

    def __init__(self, provider):
        super().__init__("Volume", provider)
        self.volumes: dict[str, FlyVolume] = {}
        self._list_volumes()

    def _list_volumes(self):
        """Read every volume of every in-scope app."""
        for org_slug, app_name in self._app_scope():
            try:
                volumes = self._get(f"/apps/{app_name}/volumes")
                if not volumes:
                    continue

                for volume in volumes:
                    volume_id = volume.get("id", "")
                    self.volumes[f"{app_name}/{volume_id}"] = FlyVolume(
                        id=volume_id,
                        name=volume.get("name", volume_id),
                        app_name=app_name,
                        org_slug=org_slug,
                        region=volume.get("region", "") or "global",
                        state=volume.get("state", "") or "",
                        size_gb=volume.get("size_gb", 0) or 0,
                        encrypted=bool(volume.get("encrypted")),
                        auto_backup_enabled=bool(volume.get("auto_backup_enabled")),
                        snapshot_retention=volume.get("snapshot_retention", 0) or 0,
                        attached_machine_id=volume.get("attached_machine_id"),
                    )
            except Exception as error:
                logger.error(
                    f"{self.service} - Error listing volumes for app {app_name}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
