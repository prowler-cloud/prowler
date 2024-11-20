from prowler.providers.azure.services.search.search_service import Search
from prowler.providers.common.provider import Provider

search_client = Search(Provider.get_global_provider())
