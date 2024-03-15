from prowler.providers.azure.services.entra.entra_service import Entra
from prowler.providers.common.common import get_global_provider

entra_client = Entra(get_global_provider())
