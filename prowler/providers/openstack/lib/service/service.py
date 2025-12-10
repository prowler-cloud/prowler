from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider

if TYPE_CHECKING:  # pragma: no cover - only for typing
    from prowler.providers.openstack.openstack_provider import OpenstackProvider


class OpenStackService:
    """Base class for all OpenStack services."""

    def __init__(
        self,
        service_name: str,
        provider: Optional["OpenstackProvider"] = None,
    ) -> None:
        provider_instance = provider or Provider.get_global_provider()
        if not provider_instance or provider_instance.type != "openstack":
            raise RuntimeError("OpenStack provider is not initialized.")

        self.service_name = service_name
        self.provider = provider_instance
        self.connection = provider_instance.connection
        self.session = provider_instance.session
        self.region = provider_instance.session.region_name
        self.project_id = provider_instance.session.project_id
        self.identity = provider_instance.identity
        self.audit_config = provider_instance.audit_config
        self.fixer_config = provider_instance.fixer_config

        logger.debug(
            f"{self.service_name} service initialized for project {self.project_id} in region {self.region}"
        )
