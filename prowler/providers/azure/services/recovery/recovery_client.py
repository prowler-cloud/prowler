from prowler.providers.azure.services.recovery.recovery_service import Recovery
from prowler.providers.common.provider import Provider

recovery_client = Recovery(Provider.get_global_provider())
