from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchService,
)
from prowler.providers.common.common import get_global_provider

opensearch_client = OpenSearchService(get_global_provider())
