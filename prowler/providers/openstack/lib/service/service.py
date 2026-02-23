from prowler.lib.logger import logger
from prowler.providers.openstack.openstack_provider import OpenstackProvider


class OpenStackService:
    """Base class for all OpenStack services."""

    def __init__(self, service_name: str, provider: OpenstackProvider) -> None:
        self.service_name = service_name
        self.provider = provider
        self.connection = provider.connection
        self.regional_connections = provider.regional_connections
        self.audited_regions = list(provider.regional_connections.keys())
        self.session = provider.session
        self.region = (
            provider.session.region_name
            or ", ".join(provider.session.regions or [])
            or "global"
        )
        self.project_id = provider.session.project_id
        self.identity = provider.identity
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        logger.debug(
            f"{self.service_name} service initialized for project {self.project_id} in region {self.region}"
        )
