from prowler.providers.azure.services.aks.aks_service import AKS
from prowler.providers.common.common import get_global_provider

aks_client = AKS(get_global_provider())
