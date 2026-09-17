from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.functiongraph.functiongraph_service import (
    FunctionGraph,
)

functiongraph_client = FunctionGraph(Provider.get_global_provider())
