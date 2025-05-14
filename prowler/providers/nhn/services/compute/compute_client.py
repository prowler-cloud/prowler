from prowler.providers.common.provider import Provider
from prowler.providers.nhn.services.compute.compute_service import NHNComputeService

compute_client = NHNComputeService(Provider.get_global_provider())
