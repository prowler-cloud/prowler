from prowler.providers.azure.services.entra.entra_service import Entra
from prowler.providers.common.provider import Provider

entra_client = Entra(Provider.get_global_provider())
