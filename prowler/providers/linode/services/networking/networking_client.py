from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.networking.networking_service import (
    NetworkingService,
)

networking_client = NetworkingService(Provider.get_global_provider())
