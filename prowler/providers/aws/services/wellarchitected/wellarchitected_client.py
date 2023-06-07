from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)

wellarchitected_client = WellArchitected(current_audit_info)
