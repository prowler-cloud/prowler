from prowler.providers.azure.services.monitor.monitor_service import Monitor
from prowler.providers.common.provider import Provider

monitor_client = Monitor(Provider.get_global_provider())
