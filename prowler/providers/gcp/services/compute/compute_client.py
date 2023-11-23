from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.compute.compute_service import Compute

compute_client = Compute(global_provider)
