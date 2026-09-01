from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.fly.lib.service.service import FlyService


class FlyMachineMount(BaseModel):
    """A volume mounted into a Fly.io machine."""

    volume: str
    name: str = ""
    path: str = ""
    size_gb: int = 0
    encrypted: bool = False


class FlyMachinePort(BaseModel):
    """A port published by a Fly.io machine service to the public edge."""

    port: Optional[int] = None
    handlers: list[str] = Field(default_factory=list)
    force_https: bool = False


class FlyMachineService(BaseModel):
    """A service definition of a Fly.io machine."""

    protocol: str = ""
    internal_port: Optional[int] = None
    ports: list[FlyMachinePort] = Field(default_factory=list)


class FlyMachine(BaseModel):
    """A Fly.io machine and its security-relevant configuration."""

    id: str
    name: str
    app_name: str
    org_slug: str
    region: str = "global"
    state: str = ""
    image: str = ""
    image_digest: str = ""
    image_registry: str = ""
    image_repository: str = ""
    env: dict[str, str] = Field(default_factory=dict)
    services: list[FlyMachineService] = Field(default_factory=list)
    mounts: list[FlyMachineMount] = Field(default_factory=list)
    app_secret_names: list[str] = Field(default_factory=list)


class Machine(FlyService):
    """Retrieve Fly.io machines with their image, network and secret configuration."""

    def __init__(self, provider):
        super().__init__("Machine", provider)
        self.machines: dict[str, FlyMachine] = {}
        self._list_machines()

    def _list_machines(self):
        """Read every machine of every in-scope app."""
        for org_slug, app_name in self._app_scope():
            try:
                machines = self._get(f"/apps/{app_name}/machines")
                if not machines:
                    continue

                secret_names = self._list_app_secret_names(app_name)

                for machine in machines:
                    config = machine.get("config", {}) or {}
                    image_ref = machine.get("image_ref", {}) or {}
                    machine_id = machine.get("id", "")

                    self.machines[f"{app_name}/{machine_id}"] = FlyMachine(
                        id=machine_id,
                        name=machine.get("name", machine_id),
                        app_name=app_name,
                        org_slug=org_slug,
                        region=machine.get("region", "") or "global",
                        state=machine.get("state", ""),
                        image=config.get("image", ""),
                        image_digest=image_ref.get("digest", "") or "",
                        image_registry=image_ref.get("registry", "") or "",
                        image_repository=image_ref.get("repository", "") or "",
                        env={
                            key: str(value)
                            for key, value in (config.get("env") or {}).items()
                        },
                        services=[
                            FlyMachineService(
                                protocol=service.get("protocol", "") or "",
                                internal_port=service.get("internal_port"),
                                ports=[
                                    FlyMachinePort(
                                        port=port.get("port"),
                                        handlers=port.get("handlers") or [],
                                        force_https=bool(port.get("force_https")),
                                    )
                                    for port in (service.get("ports") or [])
                                ],
                            )
                            for service in (config.get("services") or [])
                        ],
                        mounts=[
                            FlyMachineMount(
                                volume=mount.get("volume", ""),
                                name=mount.get("name", "") or "",
                                path=mount.get("path", "") or "",
                                size_gb=mount.get("size_gb", 0) or 0,
                                encrypted=bool(mount.get("encrypted")),
                            )
                            for mount in (config.get("mounts") or [])
                        ],
                        app_secret_names=secret_names,
                    )
            except Exception as error:
                logger.error(
                    f"{self.service} - Error listing machines for app {app_name}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_app_secret_names(self, app_name: str) -> list[str]:
        """Read the names of the Fly secrets set on an app.

        Only secret names and digests are returned by the Fly.io API; values are
        never retrievable, so nothing sensitive is read by the scan.
        """
        try:
            response = self._get(f"/apps/{app_name}/secrets")
            if not response:
                return []
            return [
                secret.get("name", "")
                for secret in response.get("secrets", []) or []
                if secret.get("name")
            ]
        except Exception as error:
            logger.error(
                f"{self.service} - Error listing secrets for app {app_name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []
