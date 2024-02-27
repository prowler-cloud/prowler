from prowler.providers.aws.services.cloudwatch.cloudwatch_service import CloudWatch
from prowler.providers.common.common import get_global_provider

cloudwatch_client = CloudWatch(get_global_provider())
