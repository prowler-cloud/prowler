from prowler.providers.common.provider import Provider
from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancers,
)

loadbalancer_client = LoadBalancers(Provider.get_global_provider())
