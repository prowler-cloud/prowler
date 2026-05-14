from prowler.providers.common.provider import Provider
from prowler.providers.openstack.services.compute.compute_service import Compute

compute_client = Compute(Provider.get_global_provider())
