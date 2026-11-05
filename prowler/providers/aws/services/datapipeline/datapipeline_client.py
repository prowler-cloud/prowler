from prowler.providers.aws.services.datapipeline.datapipeline_service import (
    DataPipeline,
)
from prowler.providers.common.provider import Provider

datapipeline_client = DataPipeline(Provider.get_global_provider())
