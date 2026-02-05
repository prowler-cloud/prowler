from prowler.providers.common.provider import Provider
from prowler.providers.openstack.services.network.network_service import (  # noqa: E501
    Network,
)

network_client = Network(Provider.get_global_provider())
