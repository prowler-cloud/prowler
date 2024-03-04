from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.gke.gke_service import GKE

gke_client = GKE(get_global_provider())
