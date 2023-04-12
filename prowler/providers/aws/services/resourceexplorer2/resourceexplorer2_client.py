from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service import (
    ResourceExplorer2,
)

resource_explorer_2_client = ResourceExplorer2(current_audit_info)
