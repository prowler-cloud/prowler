from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchService,
)
from prowler.providers.common.provider import Provider

opensearch_client = OpenSearchService(Provider.get_global_provider())
