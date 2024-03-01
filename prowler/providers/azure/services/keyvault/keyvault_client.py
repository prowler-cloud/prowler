from prowler.providers.azure.services.keyvault.keyvault_service import KeyVault
from prowler.providers.common.common import get_global_provider

keyvault_client = KeyVault(get_global_provider())
