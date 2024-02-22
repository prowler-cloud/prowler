from prowler.providers.aws.services.autoscaling.autoscaling_service import AutoScaling
from prowler.providers.common.common import get_global_provider

autoscaling_client = AutoScaling(get_global_provider())
