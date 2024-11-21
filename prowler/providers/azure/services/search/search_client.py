from prowler.providers.azure.services.search.search_service import Search
from prowler.providers.common.provider import Provider

search_client = AISearch(Provider.get_global_provider())
