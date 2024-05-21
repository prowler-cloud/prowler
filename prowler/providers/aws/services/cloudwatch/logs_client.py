from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
from prowler.providers.common.provider import Provider

logs_client = Logs(Provider.get_global_provider())
