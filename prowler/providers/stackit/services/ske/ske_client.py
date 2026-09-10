from prowler.providers.common.provider import Provider
from prowler.providers.stackit.services.ske.ske_service import SKEService

ske_client = SKEService(Provider.get_global_provider())
