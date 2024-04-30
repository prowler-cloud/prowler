from prowler.providers.azure.services.aks.aks_service import AKS
from prowler.providers.common.provider import Provider

aks_client = AKS(Provider.get_global_provider())
