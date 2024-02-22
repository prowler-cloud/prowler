from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)
from prowler.providers.common.common import get_global_provider

wellarchitected_client = WellArchitected(get_global_provider())
