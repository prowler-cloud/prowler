from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.intune.intune_service import Intune

intune_client = Intune(Provider.get_global_provider())
