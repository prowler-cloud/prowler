from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service import (
    ResourceExplorer2,
)
from prowler.providers.common.common import get_global_provider

resource_explorer_2_client = ResourceExplorer2(get_global_provider())
