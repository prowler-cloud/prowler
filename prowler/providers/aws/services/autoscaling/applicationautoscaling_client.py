from prowler.providers.aws.services.autoscaling.autoscaling_service import (
    ApplicationAutoScaling,
)
from prowler.providers.common.provider import Provider

applicationautoscaling_client = ApplicationAutoScaling(Provider.get_global_provider())
