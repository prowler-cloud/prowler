from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.compute.compute_service import Compute

compute_client = Compute(get_global_provider())
