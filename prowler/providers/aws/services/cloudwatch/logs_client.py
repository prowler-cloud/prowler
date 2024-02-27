from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
from prowler.providers.common.common import get_global_provider

logs_client = Logs(get_global_provider())
