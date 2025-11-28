from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
    ActionTrail,
)
from prowler.providers.common.provider import Provider

actiontrail_client = ActionTrail(Provider.get_global_provider())
