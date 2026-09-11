from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.fly.lib.service.service import FlyService

MIN_PORT = 1
MAX_PORT = 65535


class FlyMachineMount(BaseModel):
    """A volume mounted into a Fly.io machine."""

    volume: str
    name: str = ""
    path: str = ""
    size_gb: int = 0
    encrypted: bool = False


class FlyMachinePort(BaseModel):
    """A port, or inclusive port range, published by a Fly.io machine service.

    The Machines API publishes either a single ``port`` or a ``start_port`` /
    ``end_port`` range on the Fly.io edge; both forms are kept as returned.
    """

    port: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    handlers: list[str] = Field(default_factory=list)
    force_https: bool = False

    def published_ports(self) -> set[int]:
        """Expand the entry into the set of edge ports it publishes.

        ``start_port`` and ``end_port`` are inclusive (official configuration
        reference). The Machines API does not document a one-sided range; it
        is read the way the Fly.io client library does (``fly-go``
        ``MachinePort.ContainsPort``), with the missing bound defaulting to
        the edge of the valid port space, which reports the larger exposure.

        Returns:
            set[int]: Every edge port published by this entry.
        """
        ports = set()
        if self.port is not None:
            ports.add(self.port)
        if self.start_port is not None or self.end_port is not None:
            start = self.start_port if self.start_port is not None else MIN_PORT
            end = self.end_port if self.end_port is not None else MAX_PORT
            start, end = sorted((start, end))
            ports.update(range(max(start, MIN_PORT), min(end, MAX_PORT) + 1))
        return ports


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
    # None when the app's secret names could not be read (not the same as none set)
    app_secret_names: Optional[list[str]] = None


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
                    machine_id = machine.get("id") or ""

                    self.machines[f"{app_name}/{machine_id}"] = FlyMachine(
                        id=machine_id,
                        name=machine.get("name") or machine_id,
                        app_name=app_name,
                        org_slug=org_slug,
                        region=machine.get("region") or "global",
                        state=machine.get("state") or "",
                        image=config.get("image") or "",
                        image_digest=image_ref.get("digest", "") or "",
                        image_registry=image_ref.get("registry", "") or "",
                        image_repository=image_ref.get("repository", "") or "",
                        env={
                            key: "" if value is None else str(value)
                            for key, value in (config.get("env") or {}).items()
                        },
                        services=[
                            FlyMachineService(
                                protocol=service.get("protocol") or "",
                                internal_port=service.get("internal_port"),
                                ports=[
                                    FlyMachinePort(
                                        port=port.get("port"),
                                        start_port=port.get("start_port"),
                                        end_port=port.get("end_port"),
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
                                volume=mount.get("volume") or "",
                                name=mount.get("name") or "",
                                path=mount.get("path") or "",
                                size_gb=mount.get("size_gb") or 0,
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

    def _list_app_secret_names(self, app_name: str) -> Optional[list[str]]:
        """Read the names of the Fly secrets set on an app.

        Only secret names and digests are requested from the Fly.io API (the
        ``show_secrets`` option is never sent), so nothing sensitive is read by
        the scan.

        Returns:
            Optional[list[str]]: The secret names, or ``None`` when the listing
            failed or was not accessible, so a gap is not mistaken for "no
            secrets".
        """
        try:
            response = self._get(f"/apps/{app_name}/secrets")
            if response is None:
                return None
            return [
                secret.get("name") or ""
                for secret in response.get("secrets", []) or []
                if secret.get("name")
            ]
        except Exception as error:
            logger.error(
                f"{self.service} - Error listing secrets for app {app_name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
