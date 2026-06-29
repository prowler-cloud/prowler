from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.compute.compute_service import ComputeService

compute_client = ComputeService(Provider.get_global_provider())
