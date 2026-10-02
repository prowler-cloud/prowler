from prowler.providers.azure.services.aiservices.aiservices_service import AIServices
from prowler.providers.common.provider import Provider

aiservices_client = AIServices(Provider.get_global_provider())
