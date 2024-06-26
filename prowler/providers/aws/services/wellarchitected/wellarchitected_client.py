from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)
from prowler.providers.common.provider import Provider

wellarchitected_client = WellArchitected(Provider.get_global_provider())
