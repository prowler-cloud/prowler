from prowler.providers.aws.services.opensearchserverless.opensearchserverless_service import (
    OpenSearchServerless,
)
from prowler.providers.common.provider import Provider

opensearchserverless_client = OpenSearchServerless(Provider.get_global_provider())
