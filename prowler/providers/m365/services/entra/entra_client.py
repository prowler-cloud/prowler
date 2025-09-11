from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.entra.entra_service import Entra

entra_client = Entra(Provider.get_global_provider())
