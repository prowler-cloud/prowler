from prowler.providers.azure.services.aisearch.aisearch_service import AISearch
from prowler.providers.common.provider import Provider

aisearch_client = AISearch(Provider.get_global_provider())
