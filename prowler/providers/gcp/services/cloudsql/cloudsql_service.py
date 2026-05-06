from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudSQL(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("sqladmin", provider)
        self.instances = []
        self._get_instances()

    def _get_instances(self):
        for project_id in self.project_ids:
            try:
                request = self.client.instances().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for instance in response.get("items", []):
                        public_ip = False
                        for address in instance.get("ipAddresses", []):
                            if address["type"] == "PRIMARY":
                                public_ip = True
                        settings = instance.get("settings", {})
                        ip_config = settings.get("ipConfiguration", {})
                        self.instances.append(
                            Instance(
                                name=instance["name"],
                                version=instance["databaseVersion"],
                                region=instance["region"],
                                ip_addresses=instance.get("ipAddresses", []),
                                public_ip=public_ip,
                                require_ssl=ip_config.get("requireSsl", False),
                                ssl_mode=ip_config.get(
                                    "sslMode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
                                ),
                                automated_backups=settings.get(
                                    "backupConfiguration", {}
                                ).get("enabled", False),
                                authorized_networks=ip_config.get(
                                    "authorizedNetworks", []
                                ),
                                flags=settings.get("databaseFlags", []),
                                high_availability=settings.get(
                                    "availabilityType", "ZONAL"
                                )
                                == "REGIONAL",
                                cmek_key_name=instance.get(
                                    "diskEncryptionConfiguration", {}
                                ).get("kmsKeyName"),
                                project_id=project_id,
                            )
                        )

                    request = self.client.instances().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Instance(BaseModel):
    name: str
    version: str
    ip_addresses: list
    region: str
    public_ip: bool
    authorized_networks: list
    require_ssl: bool
    ssl_mode: str
    automated_backups: bool
    flags: list
    high_availability: bool = False
    cmek_key_name: Optional[str] = None
    project_id: str
